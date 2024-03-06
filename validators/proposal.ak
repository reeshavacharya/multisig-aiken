use aiken/hash.{sha3_256}
use aiken/list
use aiken/bytearray
use aiken/builtin
use aiken/transaction.{OutputReference, ScriptContext, Transaction, Input, Output, NoDatum, Datum, InlineDatum, DatumHash}
use aiken/transaction/credential.{PaymentCredential, Address, VerificationKeyCredential,ScriptCredential, Inline}
use aiken/transaction/value.{PolicyId, AssetName, Value}

pub type AssetClass {
  policy: PolicyId,
  name: AssetName,
}

pub type MultiSigConstructor { 
    multisig_quorum_nft: AssetClass, 
    multisig_proposal_token: AssetClass 
}

pub type PubKey = ByteArray
 
pub type Vote = Bool

pub type CIP30Message = ByteArray

pub type Cip30Signature = ByteArray

pub type Signature { pk: PubKey, cip30_msg: CIP30Message, cip30_sig: Cip30Signature}

pub type MultiSigParameter {
    signatories_by_public_key: List<PubKey>,
    signatories_by_public_key_hash: List<PaymentCredential>,
    required_signatories: Int 
}

pub type MultiSigAction {
    Withdraw {withdraw_address: Address, withdraw_value: Value}
    UpdateMultiSigParameter (MultiSigParameter)
}

pub type MultiSigData {
    EmptyDatum
    MultiSigDatum {action: MultiSigAction, signatures: List<PaymentCredential>}
}

pub type Message {
    multisig_action: MultiSigAction,
    nonce: OutputReference,
    vote: Bool
}

pub type MultiSigRedeemer {
    ProposeActionOnChain
    AddSignatureOnChain
    RemoveSignatureOnChain
    ValidateActionOnChain
    ValidateActionOffChain (Message, List<Signature>) 
}

pub fn traceError (a: Bool, message: String) -> Bool {
    if (a) {True} else {error message}
}

pub fn when_then (a: Bool, b: Bool) -> Bool {
    a || b
}

pub fn listWithout(a: List<a>, b: List<a>)-> List <a>{
    when (a,b) is {
        ([], _)-> []
        (xs, [])-> xs
        ([x, ..xs], ys)-> if(list.has(ys, x)) {listWithout(xs, ys)} else {list.push(listWithout(xs, ys), x)}
    }
}

pub fn mergeOutputValues (outputs: List<Output>)-> Value {
    list.foldr(list.filter_map(outputs, fn(x){Some(x.value)}), value.zero(), fn(val, total){value.merge(val, total)})
}

 pub fn expectSingle(message: String, list: List<a>)-> a{
   when list is {
    [a]-> a
    _ -> error message
   }
 }

pub fn fromSome(some: Option<a>)-> Bool {
    when some is {
        Some(_) -> True
        None -> error @"fromSome Failed"
    }
}

pub fn selectLastElementAndReturn (sig_list: List<a>)-> Option<(a, List<a>)>{
    when sig_list is {
        [] -> None 
        [x] -> Some ((x, []))
        [x, ..xs] -> when selectLastElementAndReturn(xs) is {
            Some((last_element, rest)) -> Some((last_element, [x, ..rest]))
            None -> None
        }
    }
}

pub fn isScriptAddr(addr: Address)-> Bool {
    let script_cred = addr.payment_credential
    when script_cred is {
        ScriptCredential(_) -> True
        _ -> False
    } 
}

pub fn getAllScriptInputs(ctx: ScriptContext)-> List<Input>{
    let all_inputs = ctx.transaction.inputs
    list.filter(all_inputs, fn (x){isScriptAddr(x.output.address)})
}

pub fn getAllScriptOutputs (ctx: ScriptContext) -> List<Output>{
    let all_outputs = ctx.transaction.outputs
    list.filter(all_outputs, fn(x){isScriptAddr(x.address)})
}

pub fn filterInputsByAssetClass(asset_class: AssetClass, input: Input)-> Bool{
    filterOutputsByAssetClass (asset_class, input.output)
}

pub fn filterOutputsByAssetClass (asset_class: AssetClass, output: Output)-> Bool {
    let output_value = output.value
    valueMustContainAssetClass (asset_class, output_value)
}
pub fn filterOutputsByAddress(addr: Address, outputs: List<Output>)-> List<Output>{
    list.filter(outputs, fn(x){x.address==addr})
}

pub fn valueMustContainAssetClass(asset_class: AssetClass, val: Value)-> Bool{
    value.quantity_of(val, asset_class.policy, asset_class.name) ==1 
}

pub fn hasSomeDatum(outputs: List<Output>)-> Bool {
    list.all(outputs, fn(x){when x.datum is {
        NoDatum -> False
        DatumHash (..)-> True
        InlineDatum(..) -> True
    }})
}

pub fn getParametersFromReferenceInputNft(quorum_nft: AssetClass, ctx: ScriptContext)-> MultiSigParameter{
    let ref_inputs = ctx.transaction.reference_inputs 
    let nft_inputs = list.filter(ref_inputs, fn(x){filterInputsByAssetClass(quorum_nft, x)})
    expect ref_datum: MultiSigParameter = when nft_inputs is {
        [a]-> when a.output.datum is {
            NoDatum -> error @"MSE01"
            DatumHash (..)-> error @"MSE02"
            InlineDatum (data) -> data
        }
        []-> error @"MSE03"
        _ ->error @"MSE04"
    }
    ref_datum
}

pub fn parseDatum(datum: Datum)-> Data {
    when datum is {
        NoDatum -> error @"MSE01"
        DatumHash (..) -> error @"MSE02"
        InlineDatum(data) -> data
    }
}

pub fn outputAddressMustBeEqualToInputAddress(addr1: Address, addr2: Address) -> Bool {
    if (addr1 == addr2) {
        True
    }
    else {
        error @"MSE07"
    }
}

pub fn otherScriptInputsMustHaveSameScriptAddress(addr: Address, inputs: List<Input>)->Bool {
    list.all(inputs, fn(x){x.output.address == addr})
}

pub fn allUtxosMustHaveEmptyDatum (utxos: List<Output>)-> Bool { 
    let all_inline_datum = list.filter_map(utxos, fn(x){when x.datum is {
        NoDatum -> None 
        DatumHash (..)-> None 
        InlineDatum(data) -> Some(data) 
    }})
    let all_msd = list.filter(all_inline_datum, fn(x){
        expect msd: MultiSigData = x
        when msd is {
            EmptyDatum -> True 
            _ -> error @"all_msd failed"
        }    
    })
    list.length(all_msd) == list.length(utxos)
}

pub fn totalValueConsumedFrom(address: Address, inputs: List<Input>)-> Value {
    let filtered_inputs = list.filter_map(list.filter(inputs, fn(x){x.output.address == address}), fn(x){Some(x.output)}) 
    mergeOutputValues(filtered_inputs)
}

pub fn addedSignerMustBeOneOfSignatories (quorum_nft: AssetClass, sig: PaymentCredential, ctx: ScriptContext)-> Bool {
    let msp = getParametersFromReferenceInputNft(quorum_nft, ctx)
    let signatories_by_public_key_hash = msp.signatories_by_public_key_hash
    let valid_signer = list.has(signatories_by_public_key_hash, sig)
    let v_key = when sig is {
        VerificationKeyCredential(hash) -> hash
        _ -> error @"must be signed by verification key"
    }
    let valid_sign = list.has(ctx.transaction.extra_signatories, v_key)
    valid_signer && valid_sign
}

pub fn actionShouldNotBeChanged(old_msd: MultiSigData, new_msd: MultiSigData)-> Bool{
    let old_action = when old_msd is {
        MultiSigDatum {action, signatures} -> action 
        _ -> error @"old_msd must be of type multiSigDatum"
    }
    let new_action = when new_msd is {
        MultiSigDatum {action, signatures} -> action 
        _ -> error @"new_msd must be of type multiSigDatum"
    }
    if(old_action == new_action){
        True
    }
    else {
        error @"MSE09"
    }
}

pub fn oldSignaturesShouldNotBeModified(old_signatures: List<PaymentCredential>, new_signatures: List<PaymentCredential>)-> Bool {
    if (old_signatures == new_signatures){
        True
    }
    else {
        error @"MSE24"
    }
}

pub fn getProposalTokenWithVaultAddressAndRestOfInputs (proposal_token: AssetClass, script_inputs: List<Input>) -> (List<Input>, List<Input>, Address, List<Input>){
    let partition_inpus_by_proposal_token = fn (input_list: List<Input>)->(List<Input>, List<Input>){
        list.partition(input_list, fn(x){filterInputsByAssetClass(proposal_token, x)} )
    }
    let get_vault_address_and_rest_of_inputs = fn (input_list: List<Input>)-> (Address, List<Input>){
        when input_list is {
            [] -> error @"MSE08"
            [vault_input, ..rest] -> (vault_input.output.address, rest)
        }
    }
    let (proposal_token_inputs, other_script_inputs) = partition_inpus_by_proposal_token(script_inputs)
    let (vault_addr, rest_of_script_inputs) = get_vault_address_and_rest_of_inputs(other_script_inputs)
    (script_inputs, proposal_token_inputs, vault_addr, rest_of_script_inputs)
}

pub fn validateWithdrawAction(cons: MultiSigConstructor, ctx: ScriptContext, all_script_inputs: List<Input>, all_script_outptus: List<Output>, proposal_token_input_address: Address, vault_addr: Address, withdraw_value_in_proposal: Value, withdraw_address: Address)-> Bool {
    let withdrawing_to_vault = withdraw_address == vault_addr
    let all_outputs = ctx.transaction.outputs
    let vault_outputs = filterOutputsByAddress(vault_addr, all_script_outptus)
    let withdraw_outputs = filterOutputsByAddress(withdraw_address, all_outputs)
    let proposal_outputs = filterOutputsByAddress(proposal_token_input_address, all_script_outptus)
    let vault_output_value = mergeOutputValues(vault_outputs)
    let withdraw_output_value = mergeOutputValues(withdraw_outputs)
    let proposal_output_value = mergeOutputValues([expectSingle(@"MSE11", proposal_outputs)])
    let proposal_input_value = totalValueConsumedFrom(proposal_token_input_address, all_script_inputs)
    let vault_input_value = totalValueConsumedFrom(vault_addr, all_script_inputs)
    let payback_value = value.merge(vault_input_value , value.negate(withdraw_value_in_proposal))

    when_then (withdrawing_to_vault, traceError(value.lovelace_of(withdraw_output_value) >= value.lovelace_of(withdraw_value_in_proposal), @"MSE14"))
    && traceError (value.lovelace_of(vault_output_value) >= (if (withdrawing_to_vault){value.lovelace_of(vault_input_value)}else {value.lovelace_of(payback_value)} ) , @"MSE12")
    && traceError ((value.lovelace_of(proposal_output_value)>= value.lovelace_of(proposal_input_value))
                    &&(value.quantity_of(proposal_output_value, cons.multisig_proposal_token.policy, cons.multisig_proposal_token.name)==1), @"MSE15")
    && when_then ((!isScriptAddr(withdraw_address)), (traceError (hasSomeDatum(withdraw_outputs), @"MSE16")))
}

pub fn validateUpdateAction (cons: MultiSigConstructor, msp: MultiSigParameter, proposal_token_input_address: Address, quorum_addr: Address, all_script_inputs: List<Input>, all_script_outptus: List<Output>)-> Bool {
    let quorum_input_value = totalValueConsumedFrom (quorum_addr, all_script_inputs)
    let proposal_input_value = totalValueConsumedFrom(proposal_token_input_address, all_script_inputs)
    let quorum_output = expectSingle(@"MSE44", filterOutputsByAddress(quorum_addr, all_script_outptus))
    let quorum_output_value = quorum_output.value
    let proposal_output = expectSingle(@"MSE11", filterOutputsByAddress(proposal_token_input_address, all_script_outptus))
    let proposal_output_value = proposal_output.value
    let quorum_must_be_paid_back = traceError((value.lovelace_of(quorum_output_value) >= value.lovelace_of(quorum_input_value))
                                                &&(value.quantity_of(quorum_output_value, cons.multisig_quorum_nft.policy, cons.multisig_quorum_nft.name)==1), 
                                                @"MSE49")
    let proposal_must_be_paid_back = traceError((value.lovelace_of(proposal_output_value) >= value.lovelace_of(proposal_input_value))
                                                &&(value.quantity_of(proposal_output_value, cons.multisig_proposal_token.policy, cons.multisig_proposal_token.name)==1) , @"MSE15")     
    expect updated_msp: MultiSigParameter = parseDatum(quorum_output.datum)        
    let must_update_correctly = traceError(updated_msp == msp, @"MSE20")                                                                                   
    
    quorum_must_be_paid_back &&proposal_must_be_paid_back && must_update_correctly
}

pub fn validateProposeActionOnChain(cons: MultiSigConstructor, msd: MultiSigData, input: Input, output: Output, ctx: ScriptContext)->Bool {
    let input_addr = input.output.address
    let output_addr = output.address
    let output_datum = output.datum
    expect parsed_datum: MultiSigData = parseDatum(output_datum) 
    let sigs = when parsed_datum is {
        MultiSigDatum {action,signatures} -> signatures
        _ -> error @""
    }
    when msd is {
        EmptyDatum -> outputAddressMustBeEqualToInputAddress(input_addr, output_addr)
                    && addedSignerMustBeOneOfSignatories(cons.multisig_quorum_nft, expectSingle(@"MSE22", sigs),ctx)
        _ -> error @"MSE00"
    }
}

pub fn validateAddSignatureOnChain (cons: MultiSigConstructor, old_msd: MultiSigData, input: Input, output: Output, ctx: ScriptContext)->Bool {
    let input_addr = input.output.address
    let output_addr = output.address
    let output_datum = output.datum
    let old_signatures = when old_msd is {
        MultiSigDatum {action, signatures} -> signatures
        _ -> error @"old_msd must be of type MultiSigDatum"
    }
    expect new_msd: MultiSigData = parseDatum(output_datum) 
    let new_signatures = list.unique(when new_msd is {
        MultiSigDatum {action, signatures} -> signatures
        _ -> error @"" 
    })
    let (last_signature, last_item_removed_signatures) = when selectLastElementAndReturn(new_signatures) is {
        None -> error @"MSE23"
        Some (any) -> any
    } 
    outputAddressMustBeEqualToInputAddress(output_addr, input_addr)
    && actionShouldNotBeChanged (old_msd, new_msd)
    && oldSignaturesShouldNotBeModified (old_signatures, last_item_removed_signatures)
    && addedSignerMustBeOneOfSignatories(cons.multisig_quorum_nft, last_signature, ctx)
}

// pub fn validateRemoveSignatureOnChain(msd: MultiSigData, input: Input, output: Output, ctx: ScriptContext)->Bool {
//     let input_addr = input.output.address
//     let output_addr = output.address
//     let output_datum = output.datum
//     expect new_msd: MultiSigData = parseDatum(output_datum) 
//     let new_signatures = list.unique(when new_msd is {
//         MultiSigDatum {action, signatures} -> signatures
//         _ -> error @"" 
//     })
//     error @"function not implemented"
// }

pub fn validateActionOnChain(cons: MultiSigConstructor, msd: MultiSigData, ctx: ScriptContext, all_script_inputs: List<Input>, all_script_outptus: List<Output>)-> Bool {
    let (_, proposal_token_inputs, vault_addr, rest_of_other_script_inputs)= getProposalTokenWithVaultAddressAndRestOfInputs(cons.multisig_proposal_token, all_script_inputs)
    let proposal_token_input_address = (expectSingle (@"MSE31", proposal_token_inputs)).output.address
    let proposal_outputps = filterOutputsByAddress (proposal_token_input_address, all_script_outptus)
    let quorum_nft_input = expectSingle(@"MSE30", list.filter(all_script_inputs, fn(x){filterInputsByAssetClass(cons.multisig_quorum_nft, x)}))
    let quorum_addr = quorum_nft_input.output.address 
    let quorum_outputs = filterOutputsByAddress(quorum_addr, ctx.transaction.outputs)
    let vault_outputs = filterOutputsByAddress (vault_addr, all_script_outptus)
    let multisig_action = when msd is {
        MultiSigDatum {action, signatures} -> action 
        EmptyDatum -> error @"MSE29"
    }
    when multisig_action is {
        Withdraw {withdraw_address, withdraw_value} -> traceError (allUtxosMustHaveEmptyDatum(list.concat(proposal_outputps, vault_outputs)), @"MSE27")
                                                    && otherScriptInputsMustHaveSameScriptAddress (vault_addr,rest_of_other_script_inputs)
                                                    && validateWithdrawAction(cons, ctx, all_script_inputs, all_script_outptus, proposal_token_input_address, vault_addr, withdraw_value, withdraw_address)    
        UpdateMultiSigParameter (msp)  -> traceError (allUtxosMustHaveEmptyDatum(listWithout(all_script_outptus, quorum_outputs)), @"MSE28")
                                        && traceError (list.length(all_script_inputs)==2, @"MSE17")
                                        && validateUpdateAction(cons, msp, proposal_token_input_address, quorum_addr, all_script_inputs, all_script_outptus)
    }
}

pub fn handle_hex_char(x:Int)-> Int 
{
    if (x >= 48 && x <= 57) {x-48}
    else if (x >= 97 && x <= 102) {x - 97 + 10}
    else {error @"MSE37"}
}

pub fn convert_cip_message_to_decimal_and_compare_with_message_hash(original_message_hash: ByteArray, cip_message_hash: ByteArray, o_index: Int, c_index: Int)-> Bool {
    let o_first_byte= builtin.index_bytearray(original_message_hash, o_index)
    let c_first_char = handle_hex_char(builtin.index_bytearray(cip_message_hash, c_index)) * 16  
    let c_second_char = handle_hex_char(builtin.index_bytearray(cip_message_hash, (c_index+1)))  
    let c_pair_sum = c_first_char + c_second_char
    let sha3_256_hash_length_index= 31

    if (o_index > sha3_256_hash_length_index) {True}
    else if (o_first_byte == c_pair_sum){convert_cip_message_to_decimal_and_compare_with_message_hash(original_message_hash, cip_message_hash, (o_index+1), (c_index+2))}
    else {error @"MSE36"}
} 

pub fn validateActionOffChain (msg: Message, sigs: List<Signature>,cons: MultiSigConstructor, msd: MultiSigData, ctx: ScriptContext, all_script_inputs: List<Input>, all_script_outptus: List<Output>)-> Bool {
    let message_hash_from_cip30_msg = fn (cip30msg: CIP30Message) -> ByteArray{
        let full_length = bytearray.length(cip30msg)
        bytearray.slice(cip30msg, (full_length-64), full_length)
    }
    let message_hash_must_match = fn (cip30msg: CIP30Message)-> Bool {
        let original_message_hash = sha3_256(builtin.serialise_data(cip30msg))
        let cip_msg_hash = message_hash_from_cip30_msg(cip30msg)
        convert_cip_message_to_decimal_and_compare_with_message_hash(original_message_hash,cip_msg_hash, 0,0 )
    }
    let validate_signatures_in_redeemer = fn()-> Bool {
        let msp = getParametersFromReferenceInputNft(cons.multisig_quorum_nft, ctx) 
        let filtered_sigs =  list.filter(sigs, fn(x){list.has(msp.signatories_by_public_key, x.pk) 
                                                    && credential.verify_signature(x.pk, x.cip30_msg, x.cip30_sig)
                                                    && message_hash_must_match(x.cip30_msg)
                                                    && msg.vote})
        let signature_count = list.length(list.unique(filtered_sigs)) 
        traceError (signature_count >= msp.required_signatories, @"MSE35")
    }
    let proposal_token_inputs_must_be_single_and_must_be_of_nonce_id = fn(txid: OutputReference, msg_nonce_txid: OutputReference)-> Bool {
        traceError(txid == msg_nonce_txid, @"MSE34")
    }
    let (_ , proposal_token_inputs, vault_addr, rest_of_other_script_inputs)= getProposalTokenWithVaultAddressAndRestOfInputs(cons.multisig_proposal_token, all_script_inputs)
    let quorum_nft_input = expectSingle(@"MSE30", list.filter(all_script_inputs, fn(x){filterInputsByAssetClass (cons.multisig_quorum_nft, x)}))
    let quorum_addr = quorum_nft_input.output.address
    let quorum_outputs = filterOutputsByAddress(quorum_addr, ctx.transaction.outputs)
    let proposal_token_input_address = expectSingle(@"MSE33",proposal_token_inputs).output.address
    let txid = expectSingle(@"MSE33",proposal_token_inputs).output_reference
    let proposal_outputs = filterOutputsByAddress(proposal_token_input_address, all_script_outptus)
    let vault_outputs = filterOutputsByAddress(vault_addr, all_script_outptus)

    when msd is {
        EmptyDatum -> when msg.multisig_action is {
            Withdraw{withdraw_address, withdraw_value} -> 
                traceError(allUtxosMustHaveEmptyDatum(list.concat(proposal_outputs, vault_outputs)), @"MSE27")
                && proposal_token_inputs_must_be_single_and_must_be_of_nonce_id (txid, msg.nonce)
                && validate_signatures_in_redeemer()
                && otherScriptInputsMustHaveSameScriptAddress(vault_addr, rest_of_other_script_inputs)
                && validateWithdrawAction(cons, ctx, all_script_inputs, all_script_outptus,proposal_token_input_address, vault_addr, withdraw_value, withdraw_address)
            UpdateMultiSigParameter (u_msp) -> 
                traceError (allUtxosMustHaveEmptyDatum(listWithout(all_script_outptus, quorum_outputs)), @"MSE28")
                && traceError (list.length(all_script_inputs)==2, @"MSE17")
                && proposal_token_inputs_must_be_single_and_must_be_of_nonce_id(txid, msg.nonce) 
                && validate_signatures_in_redeemer()
                && validateUpdateAction(cons, u_msp, proposal_token_input_address, quorum_addr, all_script_inputs, all_script_outptus)
        }
        _other -> error @"MSE32"
    }
}

validator {
  fn multisig( msd: MultiSigData, redeemer: MultiSigRedeemer, ctx: ScriptContext) -> Bool {
    let msc = MultiSigConstructor{
        multisig_quorum_nft: AssetClass{policy: #"f4c9f9c4252d86702c2f4c2e49e6648c7cffe3c8f2b6b7d779788f50", name: "quorum"} ,
        multisig_proposal_token: AssetClass{policy: #"f4c9f9c4252d86702c2f4c2e49e6648c7cffe3c8f2b6b7d779788f50", name: "proposal"} 
    }
    let all_script_inputs = getAllScriptInputs(ctx)  
    let single_script_input = expectSingle(@"MSE42", all_script_inputs)       
    let all_script_outptus = getAllScriptOutputs(ctx)  
    let single_script_output = expectSingle(@"MSE43", all_script_outptus) 
    let input_val = single_script_input.output.value     
    let output_addr = single_script_output.address
    let output_val = single_script_output.value
    let reference_input_datum = getParametersFromReferenceInputNft(msc.multisig_quorum_nft, ctx)
    let validate_is_enough_signatures= fn(collected_sigs: List<PaymentCredential>)->Bool{
        let signatories_by_public_key_hash = reference_input_datum.signatories_by_public_key_hash
        let signed_list = list.filter(collected_sigs, fn(x){list.has(signatories_by_public_key_hash, x)})
        list.length(signed_list) >= reference_input_datum.required_signatories
    }
    let enough_signatures_on_chain = when msd is {
        EmptyDatum -> error @"MSE29"
        MultiSigDatum {action, signatures} -> validate_is_enough_signatures(signatures)
    }
    let input_value_contains_proposal_token = valueMustContainAssetClass(msc.multisig_proposal_token, input_val)
    let output_value_contains_proposal_token = valueMustContainAssetClass(msc.multisig_proposal_token, output_val)
    let validate_script_hash_for_output_address = list.has(transaction.find_script_outputs(all_script_outptus, when output_addr.payment_credential is {
            VerificationKeyCredential(..) -> error @""
            ScriptCredential (script)->script
        }),  single_script_output)
    let run_common_validation = input_value_contains_proposal_token && output_value_contains_proposal_token && validate_script_hash_for_output_address   
    when redeemer is {
        ProposeActionOnChain -> run_common_validation && validateProposeActionOnChain (msc, msd, single_script_input, single_script_output, ctx) 
        AddSignatureOnChain -> run_common_validation && validateAddSignatureOnChain (msc, msd, single_script_input, single_script_output, ctx)
        RemoveSignatureOnChain -> error @"Function not implemented."
            // run_common_validation && validateRemoveSignatureOnChain(msd, single_script_input, single_script_output, ctx)
        ValidateActionOnChain -> enough_signatures_on_chain && validateActionOnChain(msc, msd, ctx, all_script_inputs, all_script_outptus)
        ValidateGood morning everyone, I'm in college just about to leave. I might not make it in the scrum.
        ActionOffChain (msg, sigs) -> validateActionOffChain(msg, sigs, msc, msd, ctx, all_script_inputs, all_script_outptus)
    }
  }
}

test multisig_example(){
    let pk = #"5d4f58f5d89db08086d4cb0d933e2eccb38c0148586f0758b88b486f"
    let sk = #"dd8f5d45a1954e0aecf1dbcab8a2f723652f67ed5fb06c8ec27e42cc"
    let withdraw_address = Address{
        payment_credential: VerificationKeyCredential(pk),
        stake_credential: Some(Inline(VerificationKeyCredential(sk)))
    }
    let withdraw_value = value.from_lovelace(5000000)
    let msa = Withdraw {withdraw_address: withdraw_address, withdraw_value: withdraw_value}
    let msd = MultiSigDatum {action: msa, signatures: [pk] }
    let placeholder_utxo = OutputReference { transaction_id: TransactionId(""), output_index: 0 }
    let context = ScriptContext {
                purpose: Spend(placeholder_utxo),
                transaction: transaction.placeholder()
                    |> fn(transaction) {
                        Transaction { ..transaction, extra_signatories: [pk] }
                    }
                }
    multisig(msd, ProposeActionOnChain, context)            
}     