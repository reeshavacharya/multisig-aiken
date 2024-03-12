use aiken/list
use aiken/transaction.{ScriptContext, Output, InlineDatum}
use aiken/transaction/value.{PolicyId, AssetName, Value}
use aiken/transaction/credential.{Address, ScriptCredential}
use multisig/constructor.{MultiSigConstructor, AssetClass}

pub type VaultRedeemer {
  Withdraw
  Roll
}

pub fn traceIfFalse (msg: String, x: Bool)->Bool {
  if x {True}
  else {error msg} 
}

pub fn isScriptAddr(addr: Address)-> Bool {
    let script_cred = addr.payment_credential
    when script_cred is {
        ScriptCredential(_) -> True
        _ -> False
    } 
}

pub fn mergeOutputValues (outputs: List<Output>)-> Value {
    list.foldr(list.filter_map(outputs, fn(x){Some(x.value)}), value.zero(), fn(val, total){value.merge(val, total)})
}

validator {
    fn vault(datum_: Void, redeemer: VaultRedeemer, ctx: ScriptContext)-> Bool{
      let validate_for_withdraw = fn()-> Bool{
        let proposal_token = constructor.testMSC().multisig_proposal_token
        let tx_inputs= ctx.transaction.inputs 
        let proposal_token_inputs = list.filter(tx_inputs, fn(x){value.quantity_of(x.output.value, proposal_token.policy, proposal_token.name) ==1 })
        if (list.length(proposal_token_inputs)==1){True} else {error @"Vault expects exactly 1 proposal token in input"}
      }
      let validate_for_roll = fn ()-> Bool {
        let all_inputs = ctx.transaction.inputs
        let all_script_inputs = list.filter(all_inputs, fn (x){isScriptAddr(x.output.address)})
        let vault_address =  when list.head(all_script_inputs) is{
          Some (input) -> input.output.address
          None -> error @"No Script Inputs Found"
        } 
        let all_script_inputs_must_have_same_address = list.all(all_script_inputs, fn(x){x.output.address == vault_address})
        let vault_input_value =  mergeOutputValues(list.filter_map(all_script_inputs, fn(x){Some(x.output)}))
        let all_outputs = ctx.transaction.outputs
        let vault_output = list.filter(all_outputs, fn(x){x.address == vault_address})      
        let single_vault_output = fn()->Output{
          when vault_output is {
            [x] -> x 
            _ -> error @"Expected Single Vault Output"
          }
        } 
        let check_datum = single_vault_output().datum == InlineDatum(Withdraw)
        let vault_output_has_enough_value = value.lovelace_of(single_vault_output().value) >= value.lovelace_of(vault_input_value)
        traceIfFalse(@"All script inputs must belong to the vault", all_script_inputs_must_have_same_address)
        && traceIfFalse(@"Vault not paid enough", vault_output_has_enough_value)
        && traceIfFalse(@"Vault output datum must be: `{constructor:0, fields:[]}` ",check_datum)
      }
      when redeemer is {
        Withdraw-> validate_for_withdraw()
        Roll -> validate_for_roll()
      }
  }
}

