//! This example proves the knowledge of preimage to a hash chain tail, with a configurable number of elements per hash chain node.
//! The output of each step tracks the current tail of the hash chain
use bellpepper_core::{boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{derive::rand_core, Field, PrimeField};
use halo2curves::{bn256::Fr, grumpkin};
use flate2::{write::ZlibEncoder, Compression};
use generic_array::typenum::{U24, U4};
use nova_snark::{
  provider::{hyperkzg::Commitment, Bn256EngineKZG, GrumpkinEngine},
  gadgets::ecc::AllocatedPoint,
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine, Group,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};
use rand::Rng;
use std::time::{Duration, Instant};
use halo2curves::CurveAffine;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

pub const NUM_CHALLENGE_BITS: usize = 128;

#[derive(Clone, Debug)]
pub struct ScalarMulChainCircuit {
  pub num_sm_per_step: usize,
  pub comm1: Vec<[Fr; 2]>,
  pub comm2: Vec<[Fr; 2]>,
  pub rbits: Vec<[Fr; NUM_CHALLENGE_BITS]>,
}

impl ScalarMulChainCircuit {
  pub fn new(num_sm_per_step: usize) -> Self {
    let mut rng = rand::thread_rng();
    let rbits_i: [Fr; NUM_CHALLENGE_BITS] = (0..NUM_CHALLENGE_BITS).map(|_| rng.gen_bool(1.0 / 3.0))
      .map(|bit| if bit { Fr::ONE } else { Fr::ZERO })
      .collect::<Vec<_>>()
      .try_into()
      .unwrap();
    let grumpkin_random = grumpkin::G1Affine::from_xy(
      Fr::from_str_vartime("19834382608297447889961323302677467055070110053155139740545148874538063289754").unwrap(),
      Fr::from_str_vartime("20084669131162155340423162249467328031170931348295785825029782732565818853520").unwrap(),
      ).unwrap();
    #[allow(clippy::clone_on_copy)]
    let x = grumpkin_random.coordinates().unwrap().x().clone();
    #[allow(clippy::clone_on_copy)]
    let y = grumpkin_random.coordinates().unwrap().y().clone();
    let comm1 = vec![[x, y]; num_sm_per_step];
    let comm2 = vec![[x, y]; num_sm_per_step];
    let rbits = vec![rbits_i; num_sm_per_step];

    Self {
      num_sm_per_step,
      comm1,
      comm2,
      rbits,
    }
  }
}

impl StepCircuit<Fr> for ScalarMulChainCircuit {
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: ConstraintSystem<Fr>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<Fr>],
  ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
    // z_in provides the running accumulator
    assert_eq!(z_in.len(), 2);

    let mut z_out_x = AllocatedNum::alloc(cs.namespace(|| "z_out_x"), || Ok(Fr::ZERO)).unwrap();
    let mut z_out_y = AllocatedNum::alloc(cs.namespace(|| "z_out_y"), || Ok(Fr::ZERO)).unwrap();
    for i in 0..self.num_sm_per_step {
        // allocate x_i 
        let rbits_i = (0..NUM_CHALLENGE_BITS)
            .map(|j| AllocatedBit::alloc(
                cs.namespace(|| format!("x_{}", i)), 
                Some(self.rbits[i][j] == Fr::ONE)
            ))
            .collect::<Result<Vec<_>, _>>()?;

        let comm1_i = AllocatedPoint::<E2>::alloc(cs.namespace(|| format!("comm1_{}", i)), Some((self.comm1[i][0], self.comm1[i][1], false)))?;
        let scalar_mul = comm1_i.scalar_mul(cs.namespace(|| format!("scalar_mul_{}", i)), &rbits_i)?;
        let comm2_i = AllocatedPoint::<E2>::alloc(cs.namespace(|| format!("comm2_{}", i)), Some((self.comm2[i][0], self.comm2[i][1], false)))?;
        let folded = comm2_i.add(cs.namespace(|| format!("folded_{}", i)), &scalar_mul)?;
        let coords = folded.get_coordinates();
        z_out_x = coords.0.clone();
        z_out_y = coords.1.clone();
    }

    Ok(vec![z_out_x.clone(), z_out_y.clone()])
  }

  fn output(&self, z: &[Fr]) -> Vec<Fr> {
    z.to_vec()
  }
}

pub fn nova_ivc(num_steps: usize, num_sm_per_step: usize, 
    pp: PublicParams<E1, E2, ScalarMulChainCircuit, TrivialCircuit<<E2 as Engine>::Scalar>>, 
    circuit_secondary: TrivialCircuit<<E2 as Engine>::Scalar>
  ) -> Duration {
  
    let start = Instant::now();
    // produce non-deterministic advice
    let circuits = (0..num_steps)
      .map(|_| ScalarMulChainCircuit::new(num_sm_per_step))
      .collect::<Vec<_>>();
  
    let z0_primary = vec![<E1 as Engine>::Scalar::zero(), <E1 as Engine>::Scalar::zero()];
    let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];
  
      type C1 = ScalarMulChainCircuit;
      type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
      // produce a recursive SNARK
      // println!("Generating a RecursiveSNARK...");
      let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
        RecursiveSNARK::<E1, E2, C1, C2>::new(
          &pp,
          &circuits[0],
          &circuit_secondary,
          &z0_primary,
          &z0_secondary,
        )
        .unwrap();
  
      for circuit_primary in circuits.iter() {
        let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        assert!(res.is_ok());
      }
      start.elapsed()
  }

