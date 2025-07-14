#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/common/libsnark_serialization.hpp>

#include <fstream>
#include <string>

using namespace libsnark;

typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;


extern "C" int generateProof(int ageInput){

    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;

    default_r1cs_gg_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;

    pb_variable<FieldT> age, param, sum, eighteen, less, leq;

    // Definition of params used on proof
    leq.allocate(pb, "less_or_equal");
    sum.allocate(pb, "sum");
    age.allocate(pb, "age");
    param.allocate(pb, "param");
    eighteen.allocate(pb, "eighteen");
    less.allocate(pb, "less_than");    

    // Public parameters by order of allocation
    pb.set_input_sizes(1);

    // Setting the constraints
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age + param, sum), "age + param = sum");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(leq, 1, 1), "leq_value");

    // Max size of age variable (2^7) 
    const size_t num_bits = 7;

    // Gadget for compare the values
    comparison_gadget<FieldT> compare(pb, num_bits, eighteen, sum, less, leq, "compare");
    compare.generate_r1cs_constraints();

    // Atribution of values to the variables
    pb.val(param) = FieldT("3");
    pb.val(eighteen) = FieldT("21");
    pb.val(age) = FieldT(ageInput);

    pb.val(sum) = pb.val(age) + pb.val(param);

    compare.generate_r1cs_witness();
    std::cout << "Primary input: " << pb.primary_input() << std::endl;
    const r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(cs);
    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    

    // Write to a file 
    std::ofstream outfile("/home/rafael/project/zkp_data.txt");
    outfile << keypair.vk ;
    outfile << proof ;
    outfile << pb.primary_input() ;
    
    outfile.close();


    return 0;
}
