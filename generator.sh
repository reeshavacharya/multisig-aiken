mkdir -p contract-details
aiken build --trace-level verbose
aiken blueprint convert --validator quorum.quorum > contract-details/contract.quorum.script
aiken blueprint convert --validator proposal.multisig > contract-details/contract.proposal.script
aiken blueprint convert --validator vault.vault > contract-details/contract.vault.script
aiken blueprint address --validator quorum.quorum > contract-details/contract.quorum.addr
aiken blueprint address --validator proposal.multisig > contract-details/contract.proposal.addr
aiken blueprint address --validator vault.vault > contract-details/contract.vault.addr
