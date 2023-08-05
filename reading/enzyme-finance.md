# ENZYME FINANCE POC

## Run the POC

To run the enzyme hack POC, enter following in command line

```
$forge test --match-path test/EnzymeFinance.t.sol --match-path testEnzymeAttack -vvv
```

---

## Links

    Here is a link to my [blog post](https://medium.com/p/90f4d85c067e/edit) explaining the Enzyme Finance Hack

---

## Steps in creating the attack

    0. Setup a mainnet fork indexed to a block number just before the vulnerability was reported
    1. Get the paymaster library that had the vulnerability from etherscan & get `relayHub` and `forwarder` addresses
    2. Setup a mock recipient (`MockComptroller`) contract -> this can receive msgs from GSN network
    3. Setup an attacker address (relay worker)& make sure relay worker is registered against a relay manager with enough stake
    4. Setup a custom malicious forwarder contract that will verify every message regardless of who signed it
    5. Setup a new vault - here we used an existing vault already deployed on mainnet
    6. Change the Beacon of the existing GsnPaymasterFactory to the vulnerable paymaster library of step 1
    6.1 Deploy a PaymasterProxy and assign the vault address to the vault in Step 5
    7. Fund paymaster with 0.2 Ether and make a deposit to the RelayHub
    8. Craft a relay request with paymasterData is true, high value for pctRelayFee
    9. Relay worker signs the relay request
    10. Send request via relayHub::relayCall
    11. Check balances and notice that vault balance has decreased and relay worker (attacker) balance in relayhub increases

    Process of relaying requests can be repeated over and over to drain the full vault

---

## Key learnings

1. When using external contracts, specially infrastructure contracts (relayers, bridges, oracles), make sure you know the responsibilities that the external contract has delegated to the protocol. When overriding functions of external contracts, it is likely that a protocol has forgotten to include a key check/validation. As auditors, that is a good place to focus on

2. This error became critical because it combined 3 different concepts:

- missing verification of trusted forwarded
- missing check of relayer fees
- top-up of paymaster balance in `postRelayCall`

  Each of these issues is a medium impact, but combining all in the same attack vector made it critical. Always explore how different concepts can be combined to maximize the impact

3. Follow the funds - the `calculateCharge` function was responsible for calculating fee payable to relay workers. Simply following payouts would have shown the missing validation of `relayFee` percentage. Trace the path of token flows and always check for max/min values of such transfers - identify any paramater that can lead to a blow-up of values somewhere in the supply chain.
