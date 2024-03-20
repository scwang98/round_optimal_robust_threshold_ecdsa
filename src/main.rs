use std::{
    collections::BTreeMap, io,
};
use bicycl::{CL_HSMqk, Mpz, PublicKey, QFI, RandGen, SecretKey};
use curv::{BigInt, elliptic::curves::{Secp256k1, Point}};
use futures::SinkExt;
use round_optimal_robust_threshold_ecdsa::{
    *,
    ni_dkg::{NiDkgMsg, NiDkgOutput},
    tests::{Msg, Error},
};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex,
};

mod tests;

#[tokio::main]
async fn main() {
    let n: u16 = 3;
    let t: usize = 2;

    let mut simulation = Simulation::<Msg>::new();
    let mut party_output = vec![];

    let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let mut rand_gen = RandGen::new();
    rand_gen.set_seed(&seed);

    let q = Mpz::from("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    let clgroup = CL_HSMqk::with_rand_gen(&q, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

    let mut clsk = BTreeMap::<usize, SecretKey>::new();
    let mut clpk = BTreeMap::<usize, PublicKey>::new();

    // println!("Please enter a message to be signed:");
    // let mut message = String::new();
    // io::stdin().read_line(&mut message)
    //     .expect("Failed to read line");
    // message = message.trim().to_string();
    let mut message = String::from("123");

    for i in 0..n {
        // let sk_i = clgroup.secret_key_gen(&mut rand_gen);
        // let pk_i = clgroup.public_key_gen(&sk_i);
        // // clgroup.gq
        // clsk.insert(i.into(), sk_i);
        // clpk.insert(i.into(), pk_i);
    }

    {
        let sk = SecretKey::from_mpz(&clgroup, &Mpz::from("671604966133440655406527305706663267744646200876628794388571006749808185262840090123205732419535433679805200001350544129449658973418122667008431465910877525313380317151967180362385806938280281805008236189337587006088127428866910961952878766881640130430607"));
        let pk = PublicKey::from_qfi(&clgroup, &QFI::from_mpz(
            &Mpz::from("259751220378301282433937883513982122063038971348448100566143331165815915981736779327618462590525203709033912903026068585166259408434069259331004042790202688513233836531262336780677736440095415404301301412145704982353361295489922289496112992143485101135861980982019285479170063507214476663838271982747864675022951340531"),
            &Mpz::from("108508265593749372137170376907903608618972999895667796328247293757613650735466909346730068150077998328672039634854852673990325410481429732579223998971144366385223815567220461129525688064932390563380740459487372469417518872715206600634192560806413520216115112508230179758503759920134848480982989226341740737998457542629"),
            &Mpz::from("470251462529342638323754562799050019448908614315357119161957487356737222786884449165292642510899394467663377093188010470446982591877827493921261220434923523124959855193090212336670736626993600533342515074702876462772658024186358573508205386797518216564194558045343277635008112560332444584202108575203541528529983794907"),
        ));
        clsk.insert(0, sk);
        clpk.insert(0, pk);
    }
    {
        let sk = SecretKey::from_mpz(&clgroup, &Mpz::from("4334650547538548329921271704692470557212663173914309763500781963742907132443733185180834365000459190693080510401718297705457317872424822984854515331327186747181101593704108804253179601936322549037329027443817765837125678851373856438155979937352848048500684"));
        let pk = PublicKey::from_qfi(&clgroup, &QFI::from_mpz(
            &Mpz::from("141467793392302541399595460427931745628762970681351051642728129783990344330952112852475084434255570037538081367063571911529544954272241451812322501660460783769683530150996530053206946669363105382902475800273551756209532095214940092742133912842437407748013303148852273399563165656946646463070439606100710703162075359891"),
            &Mpz::from("-130993655941051931865288106208998675618685490958839599154636050083436471632698968540895912330899473354664146564898115938814256901300610208686916723485121630214125566487997291361241887088944344591974750782232234966694535775072718316916199481373783527415265168409362904496277275071481775386292708481731472890892691809037"),
            &Mpz::from("872952859898478101366450471628073935131231810599549683081903984411583779216022292310846151772767396404417548617130474622337823573231225637361985696853922439481610411623243615741838863786032130766930218328777460354280942657537650146232027818386586786324954212176089780462101030715380594692086646291190101642626651246839"),
        ));
        clsk.insert(1, sk);
        clpk.insert(1, pk);
    }
    {
        let sk = SecretKey::from_mpz(&clgroup, &Mpz::from("4538668118682143796223911762903472380645672310819317896239070887147701226316825908139060237125193381774410344550757603082037950972361136065542699711347115295178359254392829791959747781000251810965944362317806062977711788869923436739825027873879921794395481"));
        let pk = PublicKey::from_qfi(&clgroup, &QFI::from_mpz(
            &Mpz::from("169806976113965941505484968568191498301691828145966461999927132683409758701745879459320342031382730253219018554204724109234763587952215948345407430263809790657670230855915616329534913351924899537109479809982862255230008502272098807789308121591635196606945433639582144275381232647782645637453275746993347769444391067833"),
            &Mpz::from("-115112241328680713056293361625394853983991222723721669618483195627058950698171132242276453634819650830705737296031374547912810100952428185732351629765039564594449311600990169956925696096275489535281028888785033282853434718732721508883839468788698606232822588238697171094906168188381485334065297853634713891524219068683"),
            &Mpz::from("721510918932077854205251176318267821841193228665378950270528823437410052815771134696524731642239878985551449180348490218266778014049413199019893661450350201651635128410369526099458445176304105994469145241153325495299306894358397612509007490143840733350423994797415313307482904160988215753953585330215922347554193626513"),
        ));
        clsk.insert(2, sk);
        clpk.insert(2, pk);
    }

    for i in 0..n {
        let party = simulation.add_party();
        let mysk = clsk[&(i as usize)].clone();

        let mut rand = RandGen::new();
        rand.set_seed(&rand_gen.random_mpz(&clgroup.encrypt_randomness_bound()));

        let output =
            protocol_dkg_presign_sign(message.clone(), party, i, t, n.into(), clgroup.clone(), rand.clone(), clpk.clone(), mysk);
        party_output.push(output);
    }

    let _output = futures::future::try_join_all(party_output).await.unwrap();
    for (sig, pk) in &_output {
        println!("-----------------------------------");
        println!("SignatureECDSA = {}", sig);
        if let (Some(x), Some(y)) = (pk.x_coord(), pk.y_coord()) {
            println!("Public key = {{\n\tx = {},\n\ty = {}\n}}", x, y);
        }
    }
    println!("-----------------------------------");
    let failed_count = _output.iter().filter(|(sig, pk)| !sig.verify(pk, &message)).count();
    if failed_count == 0 {
        println!("All signatures verified passed!");
    } else {
        println!("Partial signature verification failed!!");
    }
}

pub async fn protocol_dkg_presign_sign<M>(
    msg: String,
    party: M,
    myid: PartyIndex,
    t: usize,
    n: usize,
    clgroup: CL_HSMqk,
    mut rand_gen: RandGen,
    clpk: BTreeMap<usize, PublicKey>,
    mysk: SecretKey,
) -> Result<(SignatureECDSA, Point<Secp256k1>), Error<M::SendError, M::ReceiveError>>`
    where
        M: Mpc<ProtocolMessage=Msg>,
{
    let parties: Vec<usize> = (0..n).collect();
    let parties_excl_myself: Vec<usize> = (0..n).filter(|j| *j != (myid as usize)).collect();

    let n_u16 = u16::try_from(n).unwrap();
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();
    let mut rounds = RoundsRouter::<Msg>::builder();
    let round0 = rounds.add_round(RoundInput::<NiDkgMsg>::broadcast(myid, n_u16));
    let round1 = rounds.add_round(RoundInput::<NonceGenMsg>::broadcast(myid, n_u16));
    let round2 = rounds.add_round(RoundInput::<MtAwcMsg>::broadcast(myid, n_u16));
    let round3 = rounds.add_round(RoundInput::<PreSignFinalMsg>::broadcast(myid, n_u16));
    let round4 = rounds.add_round(RoundInput::<OnlineSignMsg>::broadcast(myid, n_u16));
    let mut rounds = rounds.listen(incoming);

    // Step 0: DKG of x
    let my_ni_dkg_msg = NiDkgMsg::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk);

    outgoing
        .send(Outgoing::broadcast(Msg::NiDkgMsg(my_ni_dkg_msg.clone())))
        .await
        .unwrap();

    let x_dkg_messages = rounds
        .complete(round0)
        .await
        .unwrap()
        .into_vec_including_me(my_ni_dkg_msg);

    let x_dkg_output = NiDkgOutput::from_combining(
        parties.clone(),
        &x_dkg_messages,
        myid.into(),
        clgroup.clone(),
        &mut rand_gen.clone(),
        false,
        clpk.clone(),
        &mysk,
    );

    // Step 1: Generation of nonces k and gamma
    let my_nonce_gen_msg = NonceGenMsg {
        k_dkg_msg: NiDkgMsg::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk),
        gamma_dkg_msg: NiDkgMsg::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk),
    };

    outgoing
        .send(Outgoing::broadcast(Msg::NonceGenMsg(
            my_nonce_gen_msg.clone(),
        )))
        .await
        .unwrap();

    let nonce_gen_messages = rounds
        .complete(round1)
        .await
        .unwrap()
        .into_vec_including_me(my_nonce_gen_msg);

    // Step 1->2 transition: prepare input from output
    let (k_dkg_messages, gamma_dkg_messages): (Vec<_>, Vec<_>) = nonce_gen_messages
        .into_iter()
        .map(|msg| (msg.k_dkg_msg, msg.gamma_dkg_msg))
        .unzip();

    let k_dkg_output = NiDkgOutput::from_combining(
        x_dkg_output.parties.clone(),
        &k_dkg_messages,
        myid.into(),
        clgroup.clone(),
        &mut rand_gen.clone(),
        true,
        clpk.clone(),
        &mysk,
    );

    let gamma_dkg_output = NiDkgOutput::from_combining(
        x_dkg_output.parties.clone(),
        &gamma_dkg_messages,
        myid.into(),
        clgroup.clone(),
        &mut rand_gen.clone(),
        false,
        clpk.clone(),
        &mysk,
    );

    // Step 2: Nonce conversion, or MtAwc
    let (my_mta_msg, betas, nus) = MtAwcMsg::new(
        parties_excl_myself.clone(),
        myid.into(),
        clgroup.clone(),
        &mut rand_gen.clone(),
        &clpk,
        k_dkg_output.clone(),
        gamma_dkg_output.clone().share,
        x_dkg_output.clone().share,
    );

    outgoing
        .send(Outgoing::broadcast(Msg::MtAwcMsg(my_mta_msg.clone())))
        .await
        .unwrap();

    // we want MtA messages, excluding myself's, to be arranged into a BTreeMap for Step 3
    let mut mta_messages: BTreeMap<usize, MtAwcMsg> = rounds
        .complete(round2)
        .await
        .unwrap()
        .into_iter_indexed()
        .map(|(j, _, msg)| (j.into(), msg))
        .collect();
    mta_messages.insert(myid.into(), my_mta_msg);


    // Step 3: PreSign final round aka Share Revelation
    let (my_presign_final_msg, mus_to_me, nus) = PreSignFinalMsg::new(
        parties_excl_myself.clone(),
        t,
        myid.into(),
        mta_messages.clone(),
        clgroup.clone(),
        &mut rand_gen.clone(),
        mysk,
        betas,
        nus,
        gamma_dkg_output.clone(),
        x_dkg_output.clone(),
        k_dkg_output.clone().share,
    );

    outgoing
        .send(Outgoing::broadcast(Msg::PreSignFinalMsg(
            my_presign_final_msg.clone(),
        )))
        .await
        .unwrap();

    let mut presign_final_messages: BTreeMap<usize, PreSignFinalMsg> = rounds
        .complete(round3)
        .await
        .unwrap()
        .into_iter_indexed()
        .map(|(j, _, msg)| (j.into(), msg))
        .collect();
    presign_final_messages.insert(myid.into(), my_presign_final_msg);

    // and finally you may follow me; farewell he said
    let presignature = PreSignature::from(
        parties.clone(),
        myid.into(),
        mta_messages,
        presign_final_messages,
        mus_to_me,
        nus,
        gamma_dkg_output.pk,
        k_dkg_output.clone(),
    );

    // Step 4: Online Signing
    let (my_online_sign_msg, r, m) = OnlineSignMsg::new(
        msg,
        parties_excl_myself,
        t,
        myid.into(),
        x_dkg_output.clone(),
        presignature.clone(),
        k_dkg_output.share.clone(),
    );

    outgoing
        .send(Outgoing::broadcast(Msg::OnlineSignMsg(
            my_online_sign_msg.clone(),
        )))
        .await
        .unwrap();

    let mut online_sign_messages: BTreeMap<usize, OnlineSignMsg> = rounds
        .complete(round4)
        .await
        .unwrap()
        .into_iter_indexed()
        .map(|(j, _, msg)| (j.into(), msg))
        .collect();
    online_sign_messages.insert(myid.into(), my_online_sign_msg);

    let pk = x_dkg_output.pk.clone();

    let signature = SignatureECDSA::from(
        parties,
        myid.into(),
        online_sign_messages,
        r,
        m,
        presignature,
        x_dkg_output.clone(),
    );

    // let tt = x_dkg_output.pk.x_coord();
    // if let Some(xx) = x_dkg_output.pk.x_coord() {
    //     println!("ddd = {}", xx);
    // }


    Ok((signature, pk))
}
