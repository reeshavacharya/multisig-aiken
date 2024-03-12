use aiken/transaction/value.{PolicyId, AssetName, Value}
use aiken/builtin
use aiken/transaction.{OutputReference}
use aiken/transaction/credential.{ Address}

pub type AssetClass {
  policy: PolicyId,
  name: AssetName,
}

pub type MultiSigConstructor { 
    multisig_quorum_nft: AssetClass, 
    multisig_proposal_token: AssetClass 
}

pub fn testMSC() -> MultiSigConstructor{
    let common_policy = #"43a2eba06c13ab3b3b15ecb2b44ef6427303aee73292334addae734e"
    let proposal_name = #"50726f706f73616c"
    let quorum_name = #"51756f72756d"
    let quorum_nft = AssetClass{policy: common_policy, name: quorum_name}
    let proposal_token = AssetClass{policy: common_policy, name: proposal_name}
    MultiSigConstructor{
        multisig_quorum_nft: quorum_nft,
        multisig_proposal_token: proposal_token
    }
}

pub type PubKey = ByteArray
 
pub type CIP30Message = ByteArray

pub type Cip30Signature = ByteArray

pub type Signature { pk: PubKey, cip30_msg: CIP30Message, cip30_sig: Cip30Signature}

pub type MultiSigParameter {
    signatories_by_public_key: List<PubKey>,
    signatories_by_public_key_hash: List<ByteArray>,
    required_signatories: Int 
}

pub type MultiSigAction {
    Withdraw {withdraw_address: Address, withdraw_value: Value}
    UpdateMultiSigParameter (MultiSigParameter)
}

pub type MultiSigData {
    EmptyDatum
    MultiSigDatum {action: MultiSigAction, signatures: List<ByteArray>}
}

pub type Message {
    multisig_action: MultiSigAction,
    nonce: OutputReference,
    vote: Bool
}

pub type MultiSigRedeemer {
    ProposeActionOnChain
    AddSignatureOnChain
    ValidateActionOnChain
    ValidateActionOffChain (Message, List<Signature>) 
    RemoveSignatureOnChain
}