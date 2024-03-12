use aiken/hash.{sha3_256}
use aiken/list
use aiken/bytearray
use aiken/builtin
use aiken/cbor
use aiken/transaction.{OutputReference, ScriptContext, Transaction, TransactionId, Input, Output, NoDatum, Datum, InlineDatum, DatumHash, ScriptPurpose, Spend}
use aiken/transaction/credential.{PaymentCredential, StakeCredential, Address, VerificationKeyCredential,ScriptCredential, Inline}
use aiken/transaction/value.{PolicyId, AssetName, Value}
use multisig/constructor.{
MultiSigConstructor, AssetClass, PubKey, 
CIP30Message, Cip30Signature, Signature, 
MultiSigParameter, MultiSigAction, MultiSigData, 
Message, MultiSigRedeemer, EmptyDatum, 
MultiSigDatum, ProposeActionOnChain, AddSignatureOnChain,
ValidateActionOnChain, ValidateActionOffChain, RemoveSignatureOnChain,
Withdraw, UpdateMultiSigParameter }


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

pub fn addedSignerMustBeOneOfSignatories (quorum_nft: AssetClass, sig: ByteArray, ctx: ScriptContext)-> Bool {
    let msp = getParametersFromReferenceInputNft(quorum_nft, ctx)
    let signatories_by_public_key_hash = msp.signatories_by_public_key_hash
    let valid_signer = list.has(signatories_by_public_key_hash, sig)
    let v_key = when VerificationKeyCredential(sig) is {
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

pub fn oldSignaturesShouldNotBeModified(old_signatures: List<ByteArray>, new_signatures: List<ByteArray>)-> Bool {
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
    let vault_outputs = filterOutputsByAddress (vault_addr, all_script_outptus)
    let multisig_action = when msd is {
        MultiSigDatum {action, signatures} -> action 
        EmptyDatum -> error @"MSE29"
    }
    let validate_for_update_action = fn(msp: MultiSigParameter)-> Bool {
        let quorum_nft_input = expectSingle(@"MSE30", list.filter(all_script_inputs, fn(x){filterInputsByAssetClass(cons.multisig_quorum_nft, x)}))
        let quorum_addr = quorum_nft_input.output.address 
        let quorum_outputs = filterOutputsByAddress(quorum_addr, ctx.transaction.outputs)
        traceError (allUtxosMustHaveEmptyDatum(listWithout(all_script_outptus, quorum_outputs)), @"MSE28")
        && traceError (list.length(all_script_inputs)==2, @"MSE17")
        && validateUpdateAction(cons, msp, proposal_token_input_address, quorum_addr, all_script_inputs, all_script_outptus)
    }
    //common: cons all_script_inputs all_script_outptus proposal_token_input_address
    when multisig_action is {
        Withdraw {withdraw_address, withdraw_value} -> traceError (allUtxosMustHaveEmptyDatum(list.concat(proposal_outputps, vault_outputs)), @"MSE27")
                                                    && otherScriptInputsMustHaveSameScriptAddress (vault_addr,rest_of_other_script_inputs)
                                                    && validateWithdrawAction(cons, ctx, all_script_inputs, all_script_outptus, proposal_token_input_address, vault_addr, withdraw_value, withdraw_address)    
        UpdateMultiSigParameter (msp)  -> validate_for_update_action(msp)
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
        // trace bytearray.to_hex(cbor.serialise(msg_nonce_txid))
        // trace bytearray.to_hex(cbor.serialise(txid))
        traceError(txid == msg_nonce_txid, @"MSE34")
    }
    let (_ , proposal_token_inputs, vault_addr, rest_of_other_script_inputs)= getProposalTokenWithVaultAddressAndRestOfInputs(cons.multisig_proposal_token, all_script_inputs)
    let proposal_token_input_address = expectSingle(@"MSE33",proposal_token_inputs).output.address
    let txid = expectSingle(@"MSE33",proposal_token_inputs).output_reference
    let proposal_outputs = filterOutputsByAddress(proposal_token_input_address, all_script_outptus)
    let vault_outputs = filterOutputsByAddress(vault_addr, all_script_outptus)
    let validate_for_update_action = fn(u_msp: MultiSigParameter  )-> Bool {
        let quorum_nft_input = expectSingle(@"MSE30", list.filter(all_script_inputs, fn(x){filterInputsByAssetClass (cons.multisig_quorum_nft, x)}))
        let quorum_addr = quorum_nft_input.output.address
        let quorum_outputs = filterOutputsByAddress(quorum_addr, ctx.transaction.outputs)
        traceError (allUtxosMustHaveEmptyDatum(listWithout(all_script_outptus, quorum_outputs)), @"MSE28")
        && validateUpdateAction(cons, u_msp, proposal_token_input_address, quorum_addr, all_script_inputs, all_script_outptus)
    }
    when msd is {
        EmptyDatum -> when msg.multisig_action is {
            Withdraw{withdraw_address, withdraw_value} -> 
                traceError(allUtxosMustHaveEmptyDatum(list.concat(proposal_outputs, vault_outputs)), @"MSE27")
                && proposal_token_inputs_must_be_single_and_must_be_of_nonce_id (txid, msg.nonce)
                && validate_signatures_in_redeemer()
                && otherScriptInputsMustHaveSameScriptAddress(vault_addr, rest_of_other_script_inputs)
                && validateWithdrawAction(cons, ctx, all_script_inputs, all_script_outptus,proposal_token_input_address, vault_addr, withdraw_value, withdraw_address)
            UpdateMultiSigParameter (u_msp) -> 
                validate_for_update_action(u_msp)    
                && traceError (list.length(all_script_inputs)==2, @"MSE17")
                && proposal_token_inputs_must_be_single_and_must_be_of_nonce_id(txid, msg.nonce) 
                && validate_signatures_in_redeemer()
        }
        _other -> error @"MSE32"
    }
}

validator {
  fn multisig( msd: MultiSigData, redeemer: MultiSigRedeemer, ctx: ScriptContext) -> Bool {
    let msc = constructor.testMSC()
    let all_script_inputs = getAllScriptInputs(ctx)  
    let all_script_outptus = getAllScriptOutputs(ctx)  

    let reference_input_datum = getParametersFromReferenceInputNft(msc.multisig_quorum_nft, ctx)

    let enough_signatures_on_chain = fn()-> Bool{
        let validate_is_enough_signatures= fn(collected_sigs: List<ByteArray>)->Bool{
            let signatories_by_public_key_hash = reference_input_datum.signatories_by_public_key_hash
            let signed_list = list.filter(collected_sigs, fn(x){list.has(signatories_by_public_key_hash, x)})
            list.length(signed_list) >= reference_input_datum.required_signatories
        }
        when msd is {
        EmptyDatum -> error @"MSE29"
        MultiSigDatum {action, signatures} -> validate_is_enough_signatures(signatures)
        }
    }

    let run_common_validation = fn()->Bool{
        let single_script_input = expectSingle(@"MSE42", all_script_inputs) 
        let single_script_output = expectSingle(@"MSE43", all_script_outptus) 
        let input_val = single_script_input.output.value        
        let output_val = single_script_output.value
        let output_addr = single_script_output.address
        let input_value_contains_proposal_token = valueMustContainAssetClass(msc.multisig_proposal_token, input_val)
        let output_value_contains_proposal_token = valueMustContainAssetClass(msc.multisig_proposal_token, output_val)
        let validate_script_hash_for_output_address = list.has(transaction.find_script_outputs(all_script_outptus, when output_addr.payment_credential is {
                    VerificationKeyCredential(..) -> error @""
                    ScriptCredential (script)->script
                }),  single_script_output)
        input_value_contains_proposal_token && output_value_contains_proposal_token && validate_script_hash_for_output_address  
    } 

    let validate_propose_action_on_chain = fn()-> Bool {
        let single_script_input = expectSingle(@"MSE42", all_script_inputs) 
        let single_script_output = expectSingle(@"MSE43", all_script_outptus)  
        validateProposeActionOnChain (msc, msd, single_script_input, single_script_output, ctx) 
    }

    let validate_add_signature_on_chain = fn() -> Bool {
        let single_script_input = expectSingle(@"MSE42", all_script_inputs) 
        let single_script_output = expectSingle(@"MSE43", all_script_outptus) 
        validateAddSignatureOnChain (msc, msd, single_script_input, single_script_output, ctx)
    }
    when redeemer is {
        ProposeActionOnChain -> run_common_validation() && validate_propose_action_on_chain() 
        AddSignatureOnChain -> run_common_validation() && validate_add_signature_on_chain()
        RemoveSignatureOnChain -> error @"Function not implemented."
            // run_common_validation && validateRemoveSignatureOnChain(msd, single_script_input, single_script_output, ctx)
        ValidateActionOnChain -> enough_signatures_on_chain() && validateActionOnChain(msc, msd, ctx, all_script_inputs, all_script_outptus)
        ValidateActionOffChain (msg, sigs) -> validateActionOffChain(msg, sigs, msc, msd, ctx, all_script_inputs, all_script_outptus)
    }
  }
}

pub type Participants{ 
    address: Address,
    pk: PubKey,
    pkh: PaymentCredential,
    collateral: Input,
    main_fund: Input
}

pub type Receiver{
    address: Address,
    pkh: PaymentCredential,
    sh: Option<StakeCredential>
}

pub fn testMSP ()->MultiSigParameter {
    let pk_list = [#"7b11cb12ada7f8114b26e3b161c69901fe2f56577448520d24b6b0ee19324ecb",
                    #"8b86e66821681db0130de2a3c9e3b2362a10518a982561d57a4b79506148faf3",
                    #"95a8e99b38cd82c51b23659409edb1773976398404877434fed0e2991ab7a7f2",
                    #"bf6674593af0cc0b4fe7f6ff09f09514add66b1c9c22434d01b7257811b05fa4",
                    #"779b06a8a29723521568ee272bdfd54c06f8355604d0b818c729923c6d75c046",
                    #"d6e59aec7d73b711e44d8711664acc59b5ba2531b5df703f75e8505d72d7e117",
                    #"70a475106eebb9de3e54806ff7edbe85cf1d7d82a0fa011f70fea3b11e72f9cd",
                    #"abc5301b898d5176f6ede160d5fb9af87a629d642295778c178db1740294a8de",
                    #"bc2c3cb266c0ed7ce1e0633ee8dc5dd2853578028756f2fdc581e0108e96d392",
                    #"b1a760513fc7470f49a3af822e5583e9f0f783b647998415a0914dc30f6a5abe",
                    #"6636ffbe139e0d450d34720ee1127eefc3a9d5a731f47234ff3d7d923266cddb",
                    #"59c9cfa5d9558c107eec599106afa98fd17cf1fb05cb44132527d762338b722f",
                    #"73b3498d09075d3c6ca0423ec32f8578b5da056ba649b3dfca97b4046a8adf14",
                    #"a28b47ac030f8ac2e044f7c9e8d95d2b886226ba79e9f7ed201957ff63ad84da",
                    #"eb095161d3eda7c0d8f2c4fd4180efb29f17c29a0982149ea45ab3d32f0dc542",
                    #"e0bdc9707d235a1ee5345069d72ee569ba9388ffe9a76e5e76189e0fe28379c8",
                    #"bd8ee64ec321bd42d4e18c66842bec1791a83c69fce8d7dc58acb5da3db7804d",
                    #"c75145032430a7159623a1703b83c4be6da504ae64d7d7495f5e33ff2da710b8",
                    #"183a825ee8bb6747c0256d1d7b8014be6f010726cbf8129f9bdaafb8ff0f7fc4",
                    #"1e9de67b07752a70e32464eb78448e159047a2a0b6452dc5532145f085134594",
                    #"0d50726820a0dc35f67810b989d7d0c49aa265d6f11c97ce327d6eb1f0a62f2b",
                    #"44af40b3c213a6866639d48e3b687d5051fc5f9c187059b90e9c3682b596c684",
                    #"e9eac8513146b4c91fc7fe9ceb0d76381119dbbdf3b9769a80fd78ba9257f019",
                    #"ec25d338f09933f37e20ac92ec2c6d1ecda750bef5bb550a4a926c4e267af54d",
                    #"909bf6ef614f968725dcaba4023f3173df9a59b5042f36766ceccdbdb6732048",
                    #"c10e3932d957c3cad831a2256852b65ab426379a5af3541abe899bb42e946993",
                    #"066d3d07023edd20ba6062d5924f3bde8df1f5e275d8f2d3b4a58905388133fe",
                    #"b56f0b4910c523b7d2c90f95adcbde9fb83f8f3f77b9937bc55e1bf8fbd38823",
                    #"c676d027d486ef308435b4c0d53afc7534265f3c1ffaa234c442dd29f667ce6b",
                    #"cf46be701caed328d91c4372c05ff9dd97a78ef5b90e2eee59922cd77a7055dc",
                    #"f78628b8f89fb4133981d0b3397a81afbe0a4f25a1df9558db37ec8b64dd1171",
                    #"0676ee5c4f85a80b2a7a0d359420593ad853fe99c4394fa4f65055cfe8af02aa",
                    #"1d188104834ff60aafcc0ebb93fb180405b4be29dfdb3cf25602eb8563d47449",
                    #"b32934033a28a406d5d9f76f979639b08c86cb70114d4edbff986dfe9719ca34",
                    #"4c58a5db3472aedbd43e35fe0c1ce503976e42a6e19b727a82e7aac18f840dc7",
                    #"75a22c1307f92e20129008dad89367800d56340153389560ae886e5975a6b4fa",
                    #"e7850fde90c92a185dabd280ebb75ff5f8c74513b2f40bbb27af1aa11c40722e",
                    #"a533575fb86c7033380d5f7f589e242316a28765ba0f79e43351391b5fa03f7d",
                    #"0d4c22ab98951b3a22a3f28d2b6105b3a5ab40b77cb1137bac1485691065be9d",
                    #"ae6dbd897422e7a6d687a11eaad818586a5756463c2a2b0638b1512348ec8b17",
                    #"735cb73609c32ff6cc8a2eea14b68b2abdbf251b3edee9eb8bde4d2e593eb6a2",
                    #"a1032425d87a78799dfcea1a5f5c0405779c05bfd7ddaf36703c91c0ba25ba8e",
                    #"d9763228bf2212e9c766a54b4961791bfbdbe00565a129af3a73955502059f9a",
                    #"177fcdda19aa83201d23b4bdb1352137da62e95e8217c4af476d783d0f21e047",
                    #"b11f78e26ccf98c69a3e0835e27710e26e35993a41d7d2d9c75517b877f3b526",
                    #"3b04a87d505bb0a63ebaf9e65df287efb94a34598ee8b60f1de8fe4ab48ff257",
                    #"5a3f7c96913bb79bbaa04885c6055c3c0238622dc2f0ff8fe723b678a20e66bc",
                    #"124b2baa8809b297fe3b1ca5ae0e5735e8055fe0ef38f5fd4857750165898cab",
                    #"499d6901c142f15efbba57e8a9ec4fa70b41950f3c2eca7f0dc98bd1fc13f833",
                    #"57de037d1476c133ee96099d9b6b5295347b39145f5c1bbc32c6452ad50946e7"]
    let pkh_list = [#"237829940b055b03e874ace2dc3d87b9f880a3e32acb9a5514e60f8b",
                    #"4b6c5bb382fcb0da51e29408cb569dc4ef3503f211aaefabe274308a",
                    #"bb4baa2283c1119eadf7e5cd2249af2462e3081848bc3dc529a36ca2",
                    #"6154ce8f8eb9d17cf2bbdb534f73176f6d40ae47a2c7066abad4479b",
                    #"1329299a621d8abd4874e5bf3a928bc38f9f3142db6802d207554b13",
                    #"71a107d58adeaaf7a6bf5274cc4047cd01ec2908c13676a6345bf1b0",
                    #"c39df5059846c9f0409648a2b46b564f72f43ffe59d6aa74d1004630",
                    #"1e55fa2c42f1c5f70f4e0ec1da4ce2795c19af37e1858fe48adfcc55",
                    #"3adc59b6cc228400aac38e1ea7f718ab2f2d1d28cf02a5df3c0cb38d",
                    #"21cad0a54aa0c29d03724b731123d7896fbf50504990aafc095d3c2e",
                    #"fb5fe578a730295bf438b8135ca57975b68731064af3f620b150d979",
                    #"772ea1ff45493b6d4ab9ddbf4229c84923e7abbe73a8434904e2bd31",
                    #"60148f243c6d08cf56a3fa930ad63809ed548d7cc35d71214947c3e6",
                    #"294c89bf41e28f28624283ca3784acc08ac54103a5c398c6435fd438",
                    #"1d9263f62823f92780f3300d24206464bd4362a0aa668a6a4f08cdb2",
                    #"9d07a895fecfb4706421311eb48144f20af2bd73cb44641bc741b7e1",
                    #"0499cc3c9110c120dd39b9ee48cf609137cd46d63cc9549c477f213a",
                    #"9982977407906dc4d3480f656480c78eaa2dcb087038b099f3064319",
                    #"8038bbae774b0ec5707ce0826e80a147690cff521d3b1b04ccba6d99",
                    #"b3d01f29c54922b5e0b8af82a325e82490b250da1d3aefe1560f5e86",
                    #"73e4f72c4df4e2e225e30036b9fa45204ec8551f00653543174f6659",
                    #"ce75a12e670da269e72002fad47d20e93e299beba74b6508d8103039",
                    #"1dd27e3c522ae1ab6a84cff73c76cc769797e099ca1724eb0fd50eb9",
                    #"33d11ae7fdf76951e4629a09481244cb44be3c0ee2048345c43fe6e0",
                    #"44cafde2ddb000717899e267eed9c28c1bfbea2bae0a3222cea13d5e",
                    #"8f4cce93ae29fbefc94fc98835e0a55863c91a42bf940589465f96dc",
                    #"f15d2cc09fb1675b2434f56069fde23bd0eb9afe6d7e37a260f06681",
                    #"42593685115e9b01a46c1ba2f96e35ad96b36ae905b35a6640d6e9ce",
                    #"a9adc08edded65d567e8fa3e3ace771db135fafd4a535bbe33cec65e",
                    #"3ae97e05af5e5a2e797d01e7a51762ec584096d6218d76a3c8365d1a",
                    #"bd7b5a06481a3a0231b2025ac00c56117b57c103a731a671ec351e57",
                    #"7292c56460612c0c7a1ddbc149ac3256925d186b1e1a5ed69cf8727a",
                    #"ec3440a00e67b6e7143bbe6e9c9f66df54f0d8ae2f520afdd0acfd39",
                    #"e63b4d974aa864afd2f7a8ff8da9ac23dcdc4f365d152c0a0ea8981a",
                    #"57eee31c34fdb7d5744c7028b6228f09dd4b427ac1999d80d90cb4a0",
                    #"08f23fe70d519dee73deab7e51dcd2a9ebbd18727df5457f5396042c",
                    #"9605e27e5c8f0b911aa37386507257e81835176417a2d992725b0172",
                    #"3b13fcdf322216d843c4241d6c4146f632c53e6bb15336f94299c430",
                    #"97d03fb51c93be9bace576770891051d10e1ec4aa42398f429975378",
                    #"233ade5337da1ff1d93cae5c75405086e870acdf0ea5884361acdf41",
                    #"82fbb6233b1e8cb6c973625648c9bcbf3df1cfcd49a3cd77425463fd",
                    #"d4473ccff053e00ccaa3cf8239392a9c12d3c4ffc0df9e94e9942405",
                    #"ddf58b1dd574c2ea6a42032be46fe75dd57e67635d775f2840e27695",
                    #"d2f4b74a876a09dec181c72ae835b00d38f0aa9c34d6e8925be189cd",
                    #"0b20a3f5137425215ebf45674a43aa3de1a2d2ae3c7080224a889603",
                    #"572dddea55e4cace06ffe268832fa0bff898cb270704b50d4bf0ccdd",
                    #"927cbfb822ab435728a7e7a202e0edfb8c218617bab9d47b884c52e7",
                    #"6810dcaefb126f2f16898bfa5034f8d7554b8660b2747bbd0ecddf04",
                    #"16381602dd1cb898b90e98b15dd6932374dfb13a2fcb040aa3fbf21e",
                    #"d27907a1e3d8181378b41eeb04cb10f760cb54002aca981d94945520"]    
    let required_sigs = 40                    
    MultiSigParameter{
        signatories_by_public_key: pk_list,
        signatories_by_public_key_hash: pkh_list,
        required_signatories: required_sigs 
    }
}

test multisig_example(){
    let proposal_script= #"5d61ce52ec6696d94831e4f7760e48f3f28cb9329d5e4609811c83ae"
    let vault_script = #"1ba547345fdbc0fbc2bb9e6307d029541a19431d8de274816ebcd4ea"
    let quorum_script = #"f152b4d19789ef57bc14cd0088cbe63580550241450a63681ae8e407"
    let receiver_address = credential.from_verification_key(#"f0f38e07bcab0b9bbaeeffc15c2e894aa9c407ae36947fd66eddae14")
    let receiver_value = value.from_lovelace(90000000)
    let msc = constructor.testMSC()
    let quorum_datum = testMSP()                        
    let token_policy = msc.multisig_quorum_nft.policy
    let proposal_token_name = msc.multisig_proposal_token.name
    let quorum_nft_name = msc.multisig_quorum_nft.name
    let withdraw_action = Withdraw{withdraw_address: receiver_address, withdraw_value: receiver_value }
    let quorum_value = value.merge(value.from_lovelace(2459450), value.from_asset(token_policy, quorum_nft_name, 1))
    let quorum_address = credential.from_verification_key(quorum_script)
    let quorum_ref_input = Input {
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 51379 },
        output: Output{ address: quorum_address, value: quorum_value, datum: InlineDatum(quorum_datum), reference_script: None }
    }
    let signers= quorum_datum.signatories_by_public_key_hash
    let proposal_value= value.merge(value.from_lovelace(2459450), value.from_asset(token_policy, proposal_token_name , 1))
    let proposal_address = credential.from_script(proposal_script)
    let proposal_datum = MultiSigDatum {action: withdraw_action,signatures: signers}
    let proposal_input = Input {
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"ee172d4e232c3f8378993f7e4b85c322775af1c6a4943f0096358bb730fbd628"}, output_index: 0 },
        output: Output {address: proposal_address, value: proposal_value, datum: InlineDatum(proposal_datum), reference_script:Some(proposal_script) }
    }
    let vault_address = credential.from_script(vault_script)
    let vault_datum = EmptyDatum
    let vault_input_value = value.from_lovelace(15000000)
    let vault_input1 =  Input {
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 41209 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    } 
    let vault_input2 = Input {
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 42209 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    }
    let vault_input3 = Input{
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 43309 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    }
    let vault_input4 = Input { 
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 44309 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    }
    let vault_input5 = Input { 
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 45309 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    }
    let vault_input6 = Input { 
        output_reference: OutputReference{transaction_id: TransactionId{hash: #"01f4b788593d4f70de2a45c2e1e87088bfbdfa29577ae1b62aba60e095e3ab53"}, output_index: 46309 },
        output: Output {address: vault_address, value: vault_input_value, datum: InlineDatum(vault_datum), reference_script: Some(vault_script) }
    }
    let placeholder_utxo = OutputReference { transaction_id: TransactionId(""), output_index: 0 }
    let vault_output_value = value.from_lovelace(0)
    let vault_output= Output{address: vault_address, value: vault_output_value, datum: InlineDatum(vault_datum),  reference_script: None}
    let receiver_output = Output {address: receiver_address, value: receiver_value, datum: InlineDatum(EmptyDatum), reference_script: None }
    let proposal_output= Output {address: proposal_address, value: proposal_value, datum: InlineDatum(EmptyDatum), reference_script: None }
    let context = ScriptContext{
        purpose: Spend(placeholder_utxo),
        transaction: transaction.placeholder()
            |> fn(transaction){
                Transaction{..transaction, inputs: [vault_input1, vault_input2, vault_input3, vault_input4, proposal_input], reference_inputs: [quorum_ref_input], outputs: [vault_output, proposal_output, receiver_output] }
            }
    }
    let signature_1 = Signature
    {   pk: #"e9328f3aefec871e517803de2efaab12c792a9efb1f0f497a4996504b9f33c69", 
        cip30_msg: #"846a5369676e6174757265315846a2012767616464726573735839005d4f58f5d89db08086d4cb0d933e2eccb38c0148586f0758b88b486fdd8f5d45a1954e0aecf1dbcab8a2f723652f67ed5fb06c8ec27e42cc40584032326664613263646465393035316363336265623662373133363138373666653835343436623463303835393039383366386165366535386562346635316638", 
        cip30_sig: #"e6f3eb716c14bf15d7df9fba4e24d7bbbea5ee62e0274ee29c5b634feae8af7e65db5b6c8247465fa9880ca600fd7bc2c8119ca5da1786b9d2f64007b3c4bc00"}
    let signature_2 = Signature
    {   pk: #"f1b5bff866b079660dd3b9f6cd2859954687ec75e871be09cf868892258bd304", 
        cip30_msg: #"846a5369676e6174757265315846a201276761646472657373583900df6a73027304d5e91ac2b25f95435553451da99ef850035f8407888a9afc7f814e2fe5356ab3e92d4f95e7f46ea22929e4469c4df1480d5140584032326664613263646465393035316363336265623662373133363138373666653835343436623463303835393039383366386165366535386562346635316638", 
        cip30_sig: #"8e1ced262266749650314779f5d6d8152ea124017cf63452d8d00298cfd34260a631cf09d2f1bc3735ea2879023cfab50e18ce9349d890d023ec2e3421887d04"}   
    let withdraw_addr = Address 
    {   payment_credential: VerificationKeyCredential(#"bd487a1b8664875175630af29e8dc0b4836e4e9eb3ea647cb026111d"), 
        stake_credential: Some(Inline(VerificationKeyCredential(#"add487c1d7caa029660e36aada60041569263b6bc2fa0c6bf5965b34")))}     
    let ms_action = Withdraw 
    {   withdraw_address: withdraw_addr,
        withdraw_value: value.from_lovelace(97000000)}   
    let oref = OutputReference 
    {   transaction_id: TransactionId{hash: #"ee172d4e232c3f8378993f7e4b85c322775af1c6a4943f0096358bb730fbd628"},
        output_index: 0}      
    let msg= Message 
    {   multisig_action: ms_action,
        nonce: oref,
        vote: True }     
    let off_chain_action = ValidateActionOffChain (msg, [signature_1, signature_2])
    let cbor_data = bytearray.to_hex(cbor.serialise(off_chain_action))
    // trace cbor_data
    multisig(EmptyDatum, off_chain_action, context)  
}   

test cbor_data(){
    let pk_list = [#"7b11cb12ada7f8114b26e3b161c69901fe2f56577448520d24b6b0ee19324ecb",
                    #"8b86e66821681db0130de2a3c9e3b2362a10518a982561d57a4b79506148faf3",
                    #"95a8e99b38cd82c51b23659409edb1773976398404877434fed0e2991ab7a7f2",
                    #"bf6674593af0cc0b4fe7f6ff09f09514add66b1c9c22434d01b7257811b05fa4"]



    let pkh_list = [#"237829940b055b03e874ace2dc3d87b9f880a3e32acb9a5514e60f8b",
                    #"4b6c5bb382fcb0da51e29408cb569dc4ef3503f211aaefabe274308a",
                    #"bb4baa2283c1119eadf7e5cd2249af2462e3081848bc3dc529a36ca2",
                    #"6154ce8f8eb9d17cf2bbdb534f73176f6d40ae47a2c7066abad4479b"]

 
    let validate_on_chain_redeemer = EmptyDatum
    let quorum_datum = MultiSigParameter {
        signatories_by_public_key: pk_list, 
        signatories_by_public_key_hash: pkh_list, 
        required_signatories: 40
    }
    let cbor_data = bytearray.to_hex(cbor.serialise(validate_on_chain_redeemer))
    traceError(True, cbor_data)
}
