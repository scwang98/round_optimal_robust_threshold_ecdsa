use bicycl::{QFI, CipherText, PublicKey, SecretKey, CL_HSMqk, Mpz, RandGen, ClearText};
use curv::{
    arithmetic::{BasicOps, Converter, Samplable},
    cryptographic_primitives::hashing::merkle_tree::Proof,
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use futures::SinkExt;
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::{Add, Mul};
use thiserror::Error;

use crate::lagrange_coeff;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NiDkgMsg {
    parties: Vec<usize>,
    rand_cmt: QFI,
    encrypted_shares: BTreeMap<usize, QFI>,
    poly_coeff_cmt: Vec<Point<Secp256k1>>,
    proof: ProofCorrectSharing,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofCorrectSharing {
    W: QFI,
    X: Point<Secp256k1>,
    Y: QFI,
    z_r: Mpz,
    z_s: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NiDkgOutput {
    pub parties: Vec<usize>, // ids of parties, used as indexes of all hashmaps
    pub share: Scalar<Secp256k1>,
    pub pk: Point<Secp256k1>,
    pub shares_cmt: BTreeMap<usize, Point<Secp256k1>>,
    pub encrypted_shares: Option<BTreeMap<usize, CipherText>>,
}

impl NiDkgMsg {
    pub fn new(t: usize, parties: Vec<usize>, clgroup: &CL_HSMqk, rand_gen: &mut RandGen, clpk: &BTreeMap<usize, PublicKey>) -> Self {
        // make coefficients of a (t-1)-degree polynomial, and derive the shares
        // let coeffs: Vec<_> = (0..t).map(|_| Scalar::<Secp256k1>::random()).collect();
        // println!();
        // println!("coeffs = {}", coeffs[0].to_bigint());
        // println!("coeffs = {}", coeffs[1].to_bigint());
        // println!();
        let mut coeffs: Vec<Scalar<Secp256k1>> = vec![];
        coeffs.push(Scalar::<Secp256k1>::from(BigInt::from_str_radix("82509043987361866709266166844629593463734673778064814716650378780491506221459", 10).unwrap()));
        coeffs.push(Scalar::<Secp256k1>::from(BigInt::from_str_radix("103460645497111196870477922315010026982558447121811254687958208780883207696630", 10).unwrap()));

        let mut shares: BTreeMap<usize, Scalar<Secp256k1>> = BTreeMap::new();

        // since party number j's are [0..n) by default, here we use j+1 as the id in Shamir SS
        for j in &parties {
            let j_bigint = BigInt::from((j + 1) as u64);
            let s_j = coeffs
                .iter()
                .enumerate()
                .map(|(k, a)| a * Scalar::<Secp256k1>::from(j_bigint.pow(k.try_into().unwrap())))
                .sum();
            shares.insert(*j, s_j);
        }

        // let r = clgroup.secret_key_gen(rand_gen);
        // let R = clgroup.public_key_gen(&r);
        let r = SecretKey::from_mpz(clgroup, &Mpz::from("2773330851675541825282966753803088258392953095748282460943289894694260986140264129738307713831851416300465248312326000457421269171432674984317441223943087803167047115892411745792935728605292911316089736125351314895935483769661574868148475518868514654585401"));
        let R = PublicKey::from_qfi(clgroup, &QFI::from_mpz(
            &Mpz::from("87123493480070824261443233843059796675571492531159535954357897312028897114789049342957446107791871982728012702087315767189910035405844502965311758493286521437977907425355382592006070449326211619253691828447055402887848133756362521347936656447433865556010284631853164039997888017051339346026403762994168979800381366739"),
            &Mpz::from("-13791560639386992148951031466415756248522801042561338194351748169939195967821138291516115756270680391185812131338727205612819206408759988608646378320276765088378345636944263218358124435337127682654676473867041817483280612608928483184720225622873023593534861740886256595831390827808338052067134643816862378838439790041"),
            &Mpz::from("1368774682624875198897826635762023987127549782540770674318777810372452074883779518879118449246418110564313572432399716454427425104982636057564455992979465064240667489574087960784220602816608521351000052962074566116205456090237898369618139489440290841760388171484365330696423929393551321803464017433217108674065922617693"),
        ));

        let rand_cmt = R.elt();

        let encrypted_shares: BTreeMap<usize, QFI> = shares
            .iter()
            .map(|(j, share)| {
                let share_mpz = Mpz::from_bytes(share.to_bigint().to_bytes().as_slice());
                (
                    *j,
                    clgroup.encrypt_with_r(&clpk[j], &ClearText::with_mpz(clgroup, &share_mpz), &r.mpz()).c2(),
                )
            })
            .collect();

        let poly_coeff_cmt: Vec<_> = coeffs
            .iter()
            .map(|a| a * Point::<Secp256k1>::generator())
            .collect();

        let proof = ProofCorrectSharing::prove(
            clgroup,
            rand_gen,
            clpk,
            &shares,
            &poly_coeff_cmt,
            &r,
            &rand_cmt,
            &encrypted_shares,
        );
        NiDkgMsg {
            parties,
            rand_cmt,
            encrypted_shares,
            poly_coeff_cmt,
            proof,
        }
    }
}

impl NiDkgOutput {
    pub fn from_combining(
        parties: Vec<usize>,
        messages: &[NiDkgMsg],
        myid: usize,
        clgroup: CL_HSMqk,
        rand_gen: &mut RandGen,
        want_encrypted_shares: bool,
        clpk: BTreeMap<usize, PublicKey>,
        mysk: &SecretKey,
    ) -> Self {
        let honest_parties: Vec<usize> = parties
            .into_iter()
            .filter(|j| ProofCorrectSharing::verify(&messages[*j], &clgroup, &clpk))
            .collect();

        let mut x_i = Scalar::<Secp256k1>::from(0);
        let mut X = Point::<Secp256k1>::zero();
        let mut X_j_list = BTreeMap::<usize, Point<Secp256k1>>::new();

        for &j in &honest_parties {
            let ct = CipherText::new(&messages[j].rand_cmt, &messages[j].encrypted_shares[&myid]);
            let pt = clgroup.decrypt(mysk, &ct);
            x_i = x_i + Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(pt.mpz().to_bytes().as_slice()));

            X = X + &messages[j].poly_coeff_cmt[0];

            // additively make the committed shares
            for &l in &honest_parties {
                let addition = messages[j]
                    .poly_coeff_cmt
                    .iter()
                    .enumerate()
                    .map(|(k, A)| {
                        A * Scalar::<Secp256k1>::from((l + 1).pow(k.try_into().unwrap()) as u64)
                    })
                    .sum::<Point<Secp256k1>>();
                let new_X_l = &*X_j_list.entry(l).or_insert(Point::<Secp256k1>::zero()) + addition;
                X_j_list.insert(l, new_X_l);
            }
        }

        let mut c_j_list = BTreeMap::<usize, CipherText>::new();

        // combine ciphertexts of shares which is expensive and therefore optional
        if want_encrypted_shares {
            for j in &honest_parties {
                let c_j = honest_parties
                    .iter()
                    .map(|&l| CipherText::new(&messages[l].rand_cmt, &messages[l].encrypted_shares[j]))
                    .reduce(|sum, ct| clgroup.add_ciphertexts(&clpk[j], &sum, &ct, rand_gen))
                    .unwrap();
                c_j_list.insert(*j, c_j.clone());
            }
        }

        NiDkgOutput {
            parties: honest_parties,
            share: x_i,
            pk: X,
            shares_cmt: X_j_list,
            encrypted_shares: match want_encrypted_shares {
                true => Some(c_j_list),
                false => None,
            },
        }
    }
}

impl ProofCorrectSharing {
    pub fn prove(
        clgroup: &CL_HSMqk,
        rand_gen: &mut RandGen,
        clpk: &BTreeMap<usize, PublicKey>,
        shares: &BTreeMap<usize, Scalar<Secp256k1>>,
        poly_coeff_cmt: &[Point<Secp256k1>],
        r: &SecretKey,
        rand_cmt: &QFI,
        encrypted_shares: &BTreeMap<usize, QFI>,
    ) -> ProofCorrectSharing {
        // let rho = clgroup.secret_key_gen(rand_gen);
        // let W = clgroup.public_key_gen(&rho);
        let rho = Mpz::from("1131706821492587928573603535902801853880691783657364897517181287694250679482579257231276051367293721399797669699928762077596511297278039651489826162808372783254613073517431245373695429458031122487072377799934781710345703224894812133827990892307983315823000");
        // let W = PK(BinaryQF {
        //     a: BigInt::from_str_radix("86546022265225642376952567542887716020004838307902931996214064313867660360740211888886772457178956422937205152196858087421439125195747212663296897630614278738311873393002270803265903303067501290633317399380500956986981113314564679210249543932016279379533540571662416027795695898945347871600226968432582692169804460071", 10).unwrap(),
        //     b: BigInt::from_str_radix("74183356241538552435555940010638491497862161312157576784598369995789929940346830219318391864285569107439329631014796213583021849846001999284003647370528779767819790996050559220917540818134260006513795845166042858297695259894677072700895549925889571166896669334695228481609447877622944122922129544342467365734862106777", 10).unwrap(),
        //     c: BigInt::from_str_radix("1393254938597000704895513717310470024768316406817451976097802284445469458904573582039058987986109939982350103994567877747848272370341407995796554874388680534234946767498732573223283766746949100036591553897953637554362384144129798406441451715624857089906249117626367585015171032941995722140728321082583329993111254079009", 10).unwrap(),
        // });
        // let W = W.elt();
        let W = QFI::from_mpz(
            &Mpz::from("86546022265225642376952567542887716020004838307902931996214064313867660360740211888886772457178956422937205152196858087421439125195747212663296897630614278738311873393002270803265903303067501290633317399380500956986981113314564679210249543932016279379533540571662416027795695898945347871600226968432582692169804460071"),
            &Mpz::from("74183356241538552435555940010638491497862161312157576784598369995789929940346830219318391864285569107439329631014796213583021849846001999284003647370528779767819790996050559220917540818134260006513795845166042858297695259894677072700895549925889571166896669334695228481609447877622944122922129544342467365734862106777"),
            &Mpz::from("1393254938597000704895513717310470024768316406817451976097802284445469458904573582039058987986109939982350103994567877747848272370341407995796554874388680534234946767498732573223283766746949100036591553897953637554362384144129798406441451715624857089906249117626367585015171032941995722140728321082583329993111254079009"),
        );

        // let alpha = Scalar::<Secp256k1>::random();
        let alpha = Scalar::<Secp256k1>::from(BigInt::from_str_radix("67605309624780820012292511797709858269673135358900737020736222808001683631049", 10).unwrap());
        let X = &alpha * Point::<Secp256k1>::generator();

        // challenge 1
        let gamma = ProofCorrectSharing::challenge_gamma(
            clpk,
            rand_cmt,
            encrypted_shares,
            poly_coeff_cmt,
        );

        // the Y in proof is rather expensive
        let temp_pk = clpk
            .iter()
            .map(|(j, pk)| pk.exponentiation(clgroup, &gamma.pow((j + 1) as u64)))
            .reduce(|prod, pk| prod.compose(clgroup, &pk))
            .unwrap();

        let pk = PublicKey::from_qfi(clgroup, &temp_pk);
        let alpha_mpz = Mpz::from_bytes(alpha.to_bigint().to_bytes().as_slice());
        let Y = clgroup.encrypt_with_r(&pk, &ClearText::with_mpz(clgroup, &alpha_mpz), &rho).c2();

        let gamma_prime = ProofCorrectSharing::challenge_gamma_prime(&gamma, &W, &X, &Y);

        let z_r = r.mpz() * &gamma_prime + rho;

        let z_s = shares
            .iter()
            .map(|(j, s)| {
                s.mul(Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(&gamma.pow((j + 1) as u64).to_bytes())))
            })
            .sum::<Scalar<Secp256k1>>()
            .mul(Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(&gamma_prime.to_bytes())))
            .add(&alpha);

        ProofCorrectSharing { W, X, Y, z_r, z_s }
    }

    pub fn verify(msg: &NiDkgMsg, clgroup: &CL_HSMqk, clpk: &BTreeMap<usize, PublicKey>) -> bool {
        let gamma = ProofCorrectSharing::challenge_gamma(
            clpk,
            &msg.rand_cmt,
            &msg.encrypted_shares,
            &msg.poly_coeff_cmt,
        );
        let gamma_prime = ProofCorrectSharing::challenge_gamma_prime(
            &gamma,
            &msg.proof.W,
            &msg.proof.X,
            &msg.proof.Y,
        );

        // check equation 1
        println!("msg.proof.W = {:?}", msg.proof.W);
        println!("clgroup.h() = {:?}", clgroup.h());
        if msg
            .proof
            .W
            .compose(&clgroup, &msg.rand_cmt.exp(&clgroup, &gamma_prime))
            != clgroup.power_of_h(&msg.proof.z_r)
        {
            return false;
        }

        // check equation 2
        let eq2in: Point<Secp256k1> = msg
            .poly_coeff_cmt
            .iter()
            .enumerate()
            .map(|(k, A)| {
                A * &msg
                    .parties
                    .iter()
                    .map(|j| j + 1)
                    .map(|j| {
                        BigInt::from(j.pow(k.try_into().unwrap()) as u64)
                            * BigInt::from_bytes(gamma.pow(j as u64).to_bytes().as_slice())
                    })
                    .map(|exp| Scalar::<Secp256k1>::from_bigint(&exp))
                    .sum()
            })
            .sum();
        if &msg.proof.X + eq2in * Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(&gamma_prime.to_bytes()))
            != Point::<Secp256k1>::generator() * &msg.proof.z_s
        {
            return false;
        }

        //check equation 3
        let temp_pk = clpk
            .iter()
            .map(|(j, pk)| pk.exponentiation(clgroup, &gamma.pow((j + 1) as u64)))
            .reduce(|prod, pk| prod.compose(clgroup, &pk))
            .unwrap();

        let pk = PublicKey::from_qfi(clgroup, &temp_pk);
        let msg_mpz = Mpz::from_bytes(msg.proof.z_s.to_bigint().to_bytes().as_slice());
        let eq3rhs = clgroup.encrypt_with_r(&pk, &ClearText::with_mpz(clgroup, &msg_mpz), &msg.proof.z_r).c2();


        let eq3in = msg
            .parties
            .iter()
            .map(|&j| msg.encrypted_shares[&j].exp(clgroup, &gamma.pow((j + 1).try_into().unwrap())))
            .reduce(|prod, item| prod.compose(clgroup, &item))
            .unwrap();
        if msg.proof.Y.compose(clgroup, &eq3in.exp(clgroup, &gamma_prime)) != eq3rhs {
            return false;
        }

        // all checks passed
        true
    }

    pub fn challenge_gamma(
        clpk: &BTreeMap<usize, PublicKey>,
        rand_cmt: &QFI,
        encrypted_shares: &BTreeMap<usize, QFI>,
        poly_coeff_cmt: &[Point<Secp256k1>],
    ) -> Mpz {
        let mut gamma_hash = Sha256::new();
        clpk.iter()
            .for_each(|(_, pk)| gamma_hash.update(pk.to_bytes()));
        gamma_hash.update(rand_cmt.to_bytes());
        encrypted_shares
            .iter()
            .for_each(|(_, ct)| gamma_hash.update(&ct.to_bytes()));
        poly_coeff_cmt
            .iter()
            .for_each(|point| gamma_hash.update(point.to_bytes(true)));

        let gamma_hash = gamma_hash.finalize();

        Mpz::from_bytes(&gamma_hash[..16])
    }

    pub fn challenge_gamma_prime(
        gamma: &Mpz,
        W: &QFI,
        X: &Point<Secp256k1>,
        Y: &QFI,
    ) -> Mpz {
        let mut gamma_prime_hash = Sha256::new();
        gamma_prime_hash.update(gamma.to_bytes());
        gamma_prime_hash.update(W.to_bytes());
        gamma_prime_hash.update(X.to_bytes(true));
        gamma_prime_hash.update(Y.to_bytes());
        let gamma_prime_hash = gamma_prime_hash.finalize();

        Mpz::from_bytes(&gamma_prime_hash[..16])
    }
}

// below are code for testing

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    NiDkgMsg(NiDkgMsg),
}

pub async fn protocol_ni_dkg<M>(
    party: M,
    myid: PartyIndex,
    t: usize,
    n: usize,
    clgroup: CL_HSMqk,
    mut rand_gen: RandGen,
    clpk: BTreeMap<usize, PublicKey>,
    mysk: SecretKey,
) -> Result<NiDkgOutput, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();
    let mut rounds = RoundsRouter::<Msg>::builder();
    let round1 = rounds.add_round(RoundInput::<NiDkgMsg>::broadcast(
        myid,
        n.try_into().unwrap(),
    ));
    let mut rounds = rounds.listen(incoming);

    let my_ni_dkg_msg = NiDkgMsg::new(t, (0..n).collect(), &clgroup, &mut rand_gen, &clpk);

    outgoing
        .send(Outgoing::broadcast(Msg::NiDkgMsg(my_ni_dkg_msg.clone())))
        .await
        .unwrap();

    let all_messages = rounds
        .complete(round1)
        .await
        .unwrap()
        .into_vec_including_me(my_ni_dkg_msg);

    Ok(NiDkgOutput::from_combining(
        (0..n).collect(),
        &all_messages,
        myid.into(),
        clgroup,
        &mut rand_gen,
        false,
        clpk,
        &mysk,
    ))
}

#[derive(Debug, Error)]
pub enum Error<RecvErr, SendErr> {
    Round1Send(SendErr),
    Round1Receive(RecvErr),
}


#[tokio::test]
async fn test_cl_keygen_overhead() {
    let n: u16 = 6;

    let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let mut rand_gen = RandGen::new();
    rand_gen.set_seed(&seed);

    let clgroup = CL_HSMqk::with_qnbits_rand_gen(50, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

    let mut clsk = BTreeMap::<usize, SecretKey>::new();
    let mut clpk = BTreeMap::<usize, PublicKey>::new();

    for i in 0..n {
        let sk_i = clgroup.secret_key_gen(&mut rand_gen);
        let pk_i = clgroup.public_key_gen(&sk_i);
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }
}


#[tokio::test]
async fn test_ni_dkg() {
    let n: u16 = 3;
    let t: usize = 2;

    let mut simulation = Simulation::<Msg>::new();
    let mut party_output = vec![];

    let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let mut rand_gen = RandGen::new();
    rand_gen.set_seed(&seed);

    let clgroup = CL_HSMqk::with_qnbits_rand_gen(50, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

    let mut clsk = BTreeMap::<usize, SecretKey>::new();
    let mut clpk = BTreeMap::<usize, PublicKey>::new();

    for i in 0..n {
        let sk_i = clgroup.secret_key_gen(&mut rand_gen);
        let pk_i = clgroup.public_key_gen(&sk_i);
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }

    for i in 0..n {
        let party = simulation.add_party();
        let mysk = clsk[&(i as usize)].clone();

        let mut rand = RandGen::new();
        rand.set_seed(&rand_gen.random_mpz(&clgroup.encrypt_randomness_bound()));

        let output = protocol_ni_dkg(party, i, t, n.into(), clgroup.clone(), rand.clone(), clpk.clone(), mysk);
        party_output.push(output);
    }

    let _output = futures::future::try_join_all(party_output).await.unwrap();
}
