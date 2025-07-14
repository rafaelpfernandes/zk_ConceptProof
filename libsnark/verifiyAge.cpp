#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/libsnark_serialization.hpp>

#include <fstream>

using namespace libsnark;
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

extern "C" int verifyAge(const uint8_t* proofB, int tam){
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;

    default_r1cs_gg_ppzksnark_pp::init_public_params();
    
    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof_in;
    r1cs_primary_input<FieldT> public_in;
    r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp> pk_in;
    r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp> vk_in;
	
    std::string proof(reinterpret_cast<const char*>(proofB),tam);
    // Get the file
    std::istringstream proofIn(proof);

    // Get the values from the file
    proofIn >> vk_in;
    proofIn >> proof_in;
    proofIn >> public_in;
    //infile >> pk_in;

    bool result = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(vk_in, public_in, proof_in);
    std::cout << "Proof verified: " << (result ? "YES" : "NO") << std::endl;
    return result ? 1 : 0;
}
