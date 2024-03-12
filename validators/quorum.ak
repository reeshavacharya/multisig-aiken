use aiken/list
use aiken/transaction.{ScriptContext}
use aiken/transaction/value.{PolicyId, AssetName}
use multisig/constructor.{MultiSigConstructor, AssetClass}



validator {
    fn quorum(datum_: Void, redeemer_: Void, ctx: ScriptContext)-> Bool{
      let proposal_token = constructor.testMSC().multisig_proposal_token
      let tx_inputs= ctx.transaction.inputs  
      let proposal_token_inputs = list.filter(tx_inputs, fn(x){value.quantity_of(x.output.value, proposal_token.policy, proposal_token.name) ==1 })
      if (list.length(proposal_token_inputs)==1){True} else {error @"Quorum expects exactly 1 proposal token in input"}
  }
}

