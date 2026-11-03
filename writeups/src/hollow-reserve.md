# Hollow Reserve

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{th1n_p00l_was_the_r3al_0racle}`

---

Flag: hiCTF{th1n_p00l_was_the_r3al_0racle}

## Goal
Drain the on-chain reserve vault below 10% of its initial balance (`Setup.isSolved()`).

## Deployed addresses (instance https://hollow-reserve-15d83fd51591.chall.hiddeninvestigations.net, chain id 31337)
Pulled from the Setup contract's constant getters (`Setup` = 0x14507117fd47c1A48bB072f7cf6fDdC431cb5376):

| Role | Address |
|------|---------|
| player | 0xd27ffd1EC266A361D233F51EBE25CDb6AFba4AEc |
| Vault (holds reserve token) | 0x8365b48ffd5db1a9c730563174dcc22fb6659c5f |
| Facility (credit facility) | 0xeb2795731f498125dafa067a7a5d22fb29b21ff1 |
| Collateral token (COL) | 0x628b9918eaaf0a8191972d807bb42adda95f0910 |
| Reserve token (RES) | 0x9cb7d7e2ed19424a2102cfd5cc7a19e65f58540c |
| priceFeed | 0x2a5eecde42ba8cff081326b8f24745f01441e12b |
| Flash lender (ERC-3156) | 0x7f74c6891b63b6dcf47edb0da1c723e1056a790c |
| Market | 0xc350c66f4c1398f512d6beffaa8a910a1e2d197e |
| Pool (COL/RES AMM) | 0xd29f59e98303df6a23a02fcae284b8cbc8d9aa79 |

Addresses are re-randomised per instance; re-read the Setup getters before replaying.

## Contract interfaces recovered from bytecode (no source published; IPFS metadata 404s)
- `Vault.reserveBalance()` = RES.balanceOf(vault) = 1e25. `Vault.lend(address,uint256)` (facility only) → RES.transfer.
- `Facility.borrow(uint256 collateralAmount, uint256 borrowAmount)`:
    1. `COL.transferFrom(msg.sender, facility, collateralAmount)` (reverts "facility: no collateral" if 0)
    2. `price = priceFeed.getPrice()`  (= `Pool.spotPrice()`)
    3. `require(borrowAmount <= price * collateralAmount / 1e18 * 7500/10000)` ("facility: over LTV")
    4. `collateralOf[msg.sender] += collateralAmount; debtOf[msg.sender] += borrowAmount`
    5. `Vault.lend(msg.sender, borrowAmount)`
  LTV = 7500 bps = 75%. **The LTV check only uses the collateral passed in THAT call and ignores existing debt** - but
  that alone is not enough to drain (a fair AMM + 75% LTV just decays each leverage cycle).
- `Facility.repay(uint256)` - proportional collateral release, needs real RES.
- `Pool` = Uniswap-V2-style constant-product AMM COL/RES, reserves 1e21 COL / 1e23 RES, 0.3% fee.
  `spotPrice() = reserveRes * 1e18 / reserveCol = 1e20` (i.e. 100 RES per COL).
  Custom swap wrappers: `40f788d2(uint256 amountResIn, uint256 minColOut)` buys COL (RES in → COL out);
  `dce0772c(uint256 amountColIn, uint256 minResOut)` sells COL.
- `priceFeed.getPrice()` simply forwards to `Pool.spotPrice()` (source recorded via the pool's own storage slot 0).
  No deviation guard, no TWAP - a raw, flash-manipulable spot price.
- `Flash lender` is ERC-3156: `flashLoan(receiver, token, amount, bytes)`,
  `maxFlashLoan(RES) = 5e24`, `flashFee = 0` (free). It holds 5e24 RES.
- `Market` (1e25 RES / 1e23 COL, maxDeviationBps = 500) is the *safe* oracle that is NOT wired to the facility -
  it is the decoy.

## Root cause
The facility values collateral with the pool's instantaneous spot price. A thin pool plus a free
5e24-RES flash loan lets an attacker skew the price arbitrarily inside one transaction, deposit
collateral bought at the skewed price, and borrow far more than it is worth.

## Exploit (`src/Exploit.sol`, one transaction)
1. `FlashLender.flashLoan(this, RES, 5e24, "")` - free.
2. Inside `onFlashLoan`: dump the whole 5e24 RES into the pool with `Pool.40f788d2(resBal, 0)`,
   receiving ~9.8e20 COL. Pool reserves become ~5.1e24 RES / ~2.0e19 COL → `spotPrice ≈ 2.5e23` (>1000x).
3. Deposit that COL and borrow: `Facility.borrow(colBal, vault.reserveBalance() - 5e22)`; the LTV test
   (0.75 · 2.5e23 · 9.8e20 / 1e18 ≈ 2e26) passes easily, so the vault empties down to 5e22.
4. Return the ERC-3156 magic value; the lender pulls `amount + fee` back with `transferFrom`
   (approve it in advance - do NOT self-transfer the repayment, that double-pays and reverts "ERC20: balance").
5. Sweep remaining RES/COL to the player.

Result: vault 1e25 → 5e22, `Setup.isSolved() == true`, flag served by `GET /flag`.

Deployed exploit: 0x2cfc3303eaCB6fb02aAb40BD6A423b5EA7c429ad (tx 0x7827f3a7f7d2aad40f7cb96ee18e1dc5fe2ad094f934c5d5fa26bcf0b2e032ec).

## Notes / pitfalls
- `cast send <to> 0x<4byte-selector> <args>` treats the hex as the FULL calldata and silently drops the extra
  args - build the full calldata string instead.
- Two near-identical AMMs exist (Pool and Market); confirm which one the feed actually reads
  (`priceFeed.source()`) instead of assuming.
- Local `anvil --fork-url <instance>` (with `-a 0`; the instancer 502s on the default dev accounts) gives a
  free, resettable sandbox - but the fork dies when the live instance expires.
