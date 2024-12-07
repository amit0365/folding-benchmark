//! This example proves the knowledge of preimage to a hash chain tail, with a configurable number of elements per hash chain node.
//! The output of each step tracks the current tail of the hash chain
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{derive::rand_core, Field};
use flate2::{write::ZlibEncoder, Compression};
use generic_array::typenum::{U24, U4};
use neptune::{
  circuit2::Elt,
  sponge::{
    api::{IOPattern, SpongeAPI, SpongeOp},
    circuit::SpongeCircuit,
    vanilla::{Mode::Simplex, Sponge, SpongeTrait},
  },
  Strength,
};
use nova_snark::{
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine, Group,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};
use std::time::{Duration, Instant};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

#[derive(Clone, Debug)]
pub struct HashChainCircuit<G: Group> {
  pub num_elts_per_step: usize,
  pub x_i: Vec<G::Scalar>,
}

impl<G: Group> HashChainCircuit<G> {
  // produces a preimage to be hashed
  pub fn new(num_elts_per_step: usize) -> Self {
    let mut rng = rand::thread_rng();
    let x_i = (0..num_elts_per_step)
      .map(|_| G::Scalar::random(&mut rng))
      .collect::<Vec<_>>();

    Self {
      num_elts_per_step,
      x_i,
    }
  }
}

impl<G: Group> StepCircuit<G::Scalar> for HashChainCircuit<G> {
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    // z_in provides the running digest
    assert_eq!(z_in.len(), 1);

    // allocate x_i
    let x_i = (0..self.num_elts_per_step)
      .map(|i| AllocatedNum::alloc(cs.namespace(|| format!("x_{}", i)), || Ok(self.x_i[i])))
      .collect::<Result<Vec<_>, _>>()?;

    // concatenate z_in and x_i
    let mut m = z_in.to_vec();
    m.extend(x_i.iter().cloned());

    let elt = m
      .iter()
      .map(|x| Elt::Allocated(x.clone()))
      .collect::<Vec<_>>();

    let num_absorbs = 1 + self.num_elts_per_step as u32;

    let parameter = IOPattern(vec![SpongeOp::Absorb(num_absorbs), SpongeOp::Squeeze(1u32)]);

    let pc = Sponge::<G::Scalar, U4>::api_constants(Strength::Standard);
    let mut ns = cs.namespace(|| "ns");

    let z_out = {
      let mut sponge = SpongeCircuit::new_with_constants(&pc, Simplex);
      let acc = &mut ns;

      sponge.start(parameter, None, acc);
      neptune::sponge::api::SpongeAPI::absorb(&mut sponge, num_absorbs, &elt, acc);

      let output = neptune::sponge::api::SpongeAPI::squeeze(&mut sponge, 1, acc);
      sponge.finish(acc).unwrap();
      Elt::ensure_allocated(&output[0], &mut ns.namespace(|| "ensure allocated"), true)?
    };

    Ok(vec![z_out])
  }

  fn output(&self, z: &[G::Scalar]) -> Vec<G::Scalar> {
    z.to_vec()
  }
}

pub fn nova_ivc(num_steps: usize, num_elts_per_step: usize, 
    pp: PublicParams<E1, E2, HashChainCircuit<<E1 as Engine>::GE>, TrivialCircuit<<E2 as Engine>::Scalar>>, 
    circuit_secondary: TrivialCircuit<<E2 as Engine>::Scalar>
  ) -> Duration {
  
    let start = Instant::now();
    // produce non-deterministic advice
    let circuits = (0..num_steps)
      .map(|_| HashChainCircuit::new(num_elts_per_step))
      .collect::<Vec<_>>();
  
    let z0_primary = vec![<E1 as Engine>::Scalar::zero()];
    let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];
  
      type C1 = HashChainCircuit<<E1 as Engine>::GE>;
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

