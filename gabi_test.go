// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/go-errors/errors"
	"github.com/stretchr/testify/assert"
)

var (
	testPrivK, testPrivK1, testPrivK2 *gabikeys.PrivateKey
	testPubK, testPubK1, testPubK2    *gabikeys.PublicKey
)

const (
	xmlPrivKey1 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPrivateKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <p>12511561644521105216249960315425509848310543851123625148071038103672749250653050780946327920540373585150518830678888836864183842100121288018131086700947919</p>
      <q>13175754961224278923898419496296790582860213842149399404614891067426616055648139811854869087421318470521236911637912285993998784296429335994419545592486183</q>
      <pPrime>6255780822260552608124980157712754924155271925561812574035519051836374625326525390473163960270186792575259415339444418432091921050060644009065543350473959</pPrime>
      <qPrime>6587877480612139461949209748148395291430106921074699702307445533713308027824069905927434543710659235260618455818956142996999392148214667997209772796243091</qPrime>
   </Elements>
</IssuerPrivateKey>`
	xmlPubKey1 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <n>164849270410462350104130325681247905590883554049096338805080434441472785625514686982133223499269392762578795730418568510961568211704176723141852210985181059718962898851826265731600544499072072429389241617421101776748772563983535569756524904424870652659455911012103327708213798899264261222168033763550010103177</n>
      <Z>85612209073231549357971504917706448448632620481242156140921956689865243071517333286408980597347754869291449755693386875207418733579434926868804114639149514414312088911027338251870409643059636340634892197874721564672349336579075665489514404442681614964231517891268285775435774878821304200809336437001672124945</Z>
      <S>95431387101397795194125116418957121488151703839429468857058760824105489778492929250965841783742048628875926892511288385484169300700205687919208898288594042075246841706909674758503593474606503299796011177189518412713004451163324915669592252022175131604797186534801966982736645522331999047305414834481507220892</S>
      <Bases num="6">
         <Base_0>15948796959221892486955992453179199515496923441128830967123361439118018661581037984810048354811434050038778558011395590650011565629310700360843433067202313291361609843998531962373969946197182940391414711398289105131565252299185121868561402842968555939684308560329951491463967030905495360286851791764439565922</Base_0>
         <Base_1>119523438901119086528333705353116973341573129722743063979885442255495816390473126070276442804547475203517104656193873407665058481273192071865721910619056848142740067272069428460724210705091048104466624895000063564223095487133194907203681789863578060886235105842841954519189942453426975057803871974937309502784</Base_1>
         <Base_2>21036812778930907905009726679774009067486097699134635274413938052367886222555608567065065339702690960558290977766511663461460906408225144877806673612081001465755091058944847078216758263034300782760502281865270151054157854728772298542643419836244547728225955304279190350362963560596454003412543292789187837679</Base_2>
         <Base_3>2507221674373339204944916721547102290807064604358409729371715856726643784893285066715992395214052930640947278288383410209092118436778149456628267900567208684458410552361708506911626161349456189054709967676518205745736652492505957876189855916223094854626710186459345996698113370306994139940441752005221653088</Base_3>
         <Base_4>43215325590379490852400435325847836613513274803460964568083232110934910151335113918829588414147781676586145312074043749201037447486205927144941119404243266454032858201713735324770837218773739346063812751896736791478531103409536739098007890723770126159814845238386299865793353073058783010002988453373168625327</Base_4>
         <Base_5>61146634020942775692657595021461289090915429142715194304483397998858712705680675945417056124974172620475325240482216550923967273908399017396442709297466408094303826941548068001214817725191465207971123378222070812822903173820970991987799984521470178624084174451047081964996323127069438975310975798326710264763</Base_5>
      </Bases>
   </Elements>
   <Features>
      <Epoch length="432000"></Epoch>
   </Features>
</IssuerPublicKey>`
	xmlPrivKey2 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPrivateKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <p>11899204220405157066705854076362480104861239101931883074217284817546620402667365757487512145720112988257938861512783018148367540266552183843422556696835959</p>
      <q>11687675946826056427944301889720810769697676393649416932482597289652868791085152984663910808816076612347241543876183667586150260004323007396424045765933627</q>
      <pPrime>5949602110202578533352927038181240052430619550965941537108642408773310201333682878743756072860056494128969430756391509074183770133276091921711278348417979</pPrime>
      <qPrime>5843837973413028213972150944860405384848838196824708466241298644826434395542576492331955404408038306173620771938091833793075130002161503698212022882966813</qPrime>
   </Elements>
</IssuerPrivateKey>`
	xmlPubKey2 = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<IssuerPublicKey xmlns="http://www.zurich.ibm.com/security/idemix">
   <Counter>0</Counter>
   <ExpiryDate>1700000000</ExpiryDate>
   <Elements>
      <n>139074042953200450756577573716087081093125755047959835310375736112120174400606581560965321655328552305330880412762069205250416578144697608952814011140599345836848582980530546248138864212612840364874312923816166397038873282769982501212640794354680085233677961149767121970163329979736254573701512654860500893293</n>
      <Z>42734451137499583379659313067721582376262445005019898840924212896341861721344880887076647548954065511016613532399873561753770596699950716884806217151189571670373798409647535613026097425988280287210414508240665780830389936353108210951728065700426436951835936702999674654289936428229982569295227091726810208504</Z>
      <S>126829853005972541969086001260986453668465797381061677444000682968013144068393822597398725937194773101762625079278987532636583109409344117202136151661601603097793537754186056937000748076167489862365768508194908399597522777250699581364596246205795577663373872577816687658275462617741670486719685398698263686551</S>
      <Bases num="6">
         <Base_0>40338259065130185314739658157310048192093670364817714952600609624607192408306024366086231626356707587756324374416236635377699775899652135471760526981946419799164489776538365542337621218846077191008645978143565824845696569002709540904092145615635620069766477253299607733404658708555482236387943774145644107155</Base_0>
         <Base_1>87294590926764077882765166008319250454824581316986036240948880310176122397314769805046534571305547053810590771663913726538715272940723444205499052940110064720613691982665763438729000435763267929115086526907175748438671858290067669579138779857489538782552512452684382063115068635634905118784884820252032788713</Base_1>
         <Base_2>45112630188085238903069069511798663932075329935779132383847263380203067284915894010441781813845184965705336439320602592823045182968796600558189004025038858823202813711551231906042036283775342496224178435309129468488081668058550719904823188068692199073681725733882486184478432125414991289211704253384344158081</Base_2>
         <Base_3>22895199267295669971377907000498707372807373558129284002593860052803834778891828018872532360982520545310813792866731358720045880773782974790652802346358667674975135735260730170180413669755483849990358724482246391921757338735789576941697731958222822227522297243574534946426308507662162995899206568536028623103</Base_3>
         <Base_4>29442357694189149206874997834969163436044466589167060785051742894686201256234721711106548932718033481872195748036017185452480637488189438942261880419540814690300046143608677755570098259230237537965383960964005848716674912279997266193234061274749285289871273401669268876576539473354504176111056568584915827297</Base_4>
         <Base_5>131901907144475345605474419271525166840628320727233669347338800265775060322235098813990701559838451432946945231275304351611643638306679131070017823266011946014245927069041536778330134744287743396547932833493856762058626556853615297319468923040156688227503880614709468161168272362825615977596973869772839600546</Base_5>
      </Bases>
   </Elements>
   <Features>
      <Epoch length="432000"></Epoch>
   </Features>
</IssuerPublicKey>`
)

var (
	rValues = []string{"75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251",
		"16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766",
		"13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840",
		"86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187",
		"68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513",
		"65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387"}
	testAttributes1 = []*big.Int{
		new(big.Int).SetBytes([]byte("one")),
		new(big.Int).SetBytes([]byte("two")),
		new(big.Int).SetBytes([]byte("three")),
		new(big.Int).SetBytes([]byte("four"))}
	testAttributes2 = []*big.Int{
		new(big.Int).SetBytes([]byte("one'")),
		new(big.Int).SetBytes([]byte("two'")),
		new(big.Int).SetBytes([]byte("three'")),
		new(big.Int).SetBytes([]byte("four'"))}
	testAttributes3 = []*big.Int{
		new(big.Int).SetBytes([]byte("one")),
		new(big.Int).SetBytes([]byte("two")),
		nil,
		new(big.Int).SetBytes([]byte("four"))}
	testAttributes4 = []*big.Int{
		new(big.Int).SetBytes([]byte("one")),
		nil, nil, nil}
)

func setupParameters() error {

	seed := make([]byte, 32)

	var err error
	testPrivK, testPubK, err = gabikeys.GenerateKeyPair(seed, 0, time.Now().AddDate(1, 0, 0))
	if err != nil {
		return err
	}
	testPubK.Issuer = "testPubK"

	// testPrivK1, err = gabikeys.NewPrivateKeyFromXML(xmlPrivKey1, false)
	// if err != nil {
	// 	return err
	// }
	// testPubK1, err = gabikeys.NewPublicKeyFromXML(xmlPubKey1)
	// if err != nil {
	// 	return err
	// }
	// testPubK1.Issuer = "testPubK1"
	// testPrivK2, err = gabikeys.NewPrivateKeyFromXML(xmlPrivKey2, false)
	// if err != nil {
	// 	return err
	// }
	// testPubK2, err = gabikeys.NewPublicKeyFromXML(xmlPubKey2)
	// if err != nil {
	// 	return err
	// }
	// testPubK2.Issuer = "testPubK2"
	return nil
}

func testPrivateKey(t *testing.T, privk *gabikeys.PrivateKey, strict bool) {
	//TODO do tests here on private key
}

func testPublicKey(t *testing.T, pubk *gabikeys.PublicKey, privk *gabikeys.PrivateKey) {
	//TODO do tests here on public key
}

func TestTestKeys(t *testing.T) {
	// DEAL WITH FACT THAT OLD KEYS DONT SATIFY PROOF REQUIREMENTS
	testPrivateKey(t, testPrivK, false)
	testPublicKey(t, testPubK, testPrivK)
}

func TestZkDilSignature(t *testing.T) {
	m := []byte("123")
	sig := Sign(testPubK, testPrivK, m)

	assert.True(t, sig.Verify(m), "zkDilithium did not verify, whereas it should.")
	m[0] = 0
	assert.True(t, !sig.Verify(m), "zkDilithium verifies, whereas it should not.")
}

// TODO In our case the proofU is the merkle tree stark that we are making.
// func TestProofU(t *testing.T) {
// 	keylength := 1024
// 	context, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	contributions, err := b.Commit(map[string]*big.Int{"secretkey": secret})
// 	require.NoError(t, err)
// 	proofU := b.CreateProof(createChallenge(context, nonce1, contributions, false))

// 	contrib, err := proofU.ChallengeContribution(testPubK)
// 	require.NoError(t, err)
// 	assert.True(t, proofU.VerifyWithChallenge(testPubK, createChallenge(context, nonce1, contrib, false)), "ProofU does not verify, whereas it should.")
// }

// func TestProofULogged(t *testing.T) {

// 	context := s2big("34911926065354700717429826907189165808787187263593066036316982805908526740809")
// 	nonce1 := s2big("724811585564063105609243")
// 	c := s2big("4184045431748299802782143929438273256345760339041229271411466459902660986200")
// 	U := s2big("53941714038323323772993715692602421894514053229231925255570480167011458936488064431963770862062871590815370913733046166911453850329862473697478794938988248741580237664467927006089054091941563143176094050444799012171081539721321786755307076274602717003792794453593019124224828904640592766190733869209960398955")
// 	vPrimeResponse := s2big("930401833442556048954810956066821001094106683380918922610147216724718347679854246682690061274042716015957693675615113399347898060611144526167949042936228868420203309360695585386210327439216083389841383395698722832808268885873389302262079691644125050748391319832394519920382663304621540520277648619992590872190274152359156399474623649137315708728792245711389032617438368799004840694779408839779419604877135070624376537994035936")
// 	sResponse := s2big("59776396667523329313292302350278517468587673934875085337674938789292900859071752886820910103285722288747559744087880906618151651690169988337871960870439882357345503256963847251")

// 	proofU := &ProofU{U: U, C: c, VPrimeResponse: vPrimeResponse, SResponse: sResponse}

// 	assert.True(t, proofU.Verify(testPubK, context, nonce1), "ProofU (from constants) does not verify, whereas it should.")
// }

// func TestCommitmentMessage(t *testing.T) {

// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	msg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	assert.True(t, msg.Proofs.Verify([]*gabikeys.PublicKey{testPubK}, context, nonce1, false, nil), "Commitment message proof does not verify, whereas it should.")
// }

// func TestProofS(t *testing.T) {
// 	// Silly commitment, content doesn't matter for this test
// 	exponent, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)
// 	U := new(big.Int).Exp(testPubK.S, exponent, testPubK.N)

// 	// Silly context
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)

// 	// Nonce (normally from the credential recipient)
// 	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)
// 	sig, _, err := issuer.signCommitmentAndAttributes(U, testAttributes1, nil)
// 	assert.NoError(t, err)

// 	proof, err := issuer.proveSignature(sig, nonce)
// 	assert.NoError(t, err)

// 	assert.True(t, proof.Verify(testPubK, sig, context, nonce), "ProofS does not verify, whereas is should.")

// 	// Silly nonce test
// 	assert.False(t, proof.Verify(testPubK, sig, context, big.NewInt(10)), "ProofS verifies, whereas it should not (wrong nonce).")

// 	// Silly context test
// 	assert.False(t, proof.Verify(testPubK, sig, big.NewInt(10), nonce), "ProofS verifies, whereas it should not (wrong context).")
// }

// func TestProofSLogged(t *testing.T) {
// 	context := s2big("34911926065354700717429826907189165808787187263593066036316982805908526740809")
// 	n2 := s2big("1424916368173409716606")

// 	// Signature
// 	A := s2big("66389313221915836241271893803869162372470096003861448260498566798077037255866372791540928160267561756794143545532118654736979223658343806335872047371607436291528588343320128898584874264796312130159695427439025355009934986408160536404163490935544221152821545871675088845781351195696518382628790514628112517886")
// 	e := s2big("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930207251663943512715842083759814664217")
// 	v := s2big("32427566863312925183262683355749521096160753564085736927716798279834745436154181827687524960554513739692930154573915901486008843583586162755818099731448281905764117842382407835789897633042765641230655956290191876265377547222981221260311549695231999461733778383779100992221748503727598149536948999564401095816377323412637286891625085960745712119714441272446053177642615033258689648568679017384011895908901362352242970432640019866501367925956123252426587516554347912178721773507440862343752105273189184247444400383")

// 	// Proof
// 	c := s2big("60359393410007276721785600209946099643760005142374188599509762410975853354415")
// 	eResponse := s2big("1139627737042307991725447845798004742853435356249558932466535799661640630812910641126155269500348608443317861800376689024557774460643901450316279085276256524076388421890909312661873221470626068394945683125859434135652717426417681918932528613003921792075852313319584079881881807505760375270399908999784672094")

// 	sig := &CLSignature{A: A, E: e, V: v}
// 	proof := &ProofS{C: c, EResponse: eResponse}

// 	assert.True(t, proof.Verify(testPubK, sig, context, n2), "ProofS (logged) does not verify, whereas it should.")
// }

// func TestSignatureMessage(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)
// 	_, err = issuer.IssueSignature(commitMsg.U, testAttributes1, nil, nonce2, nil)
// 	assert.NoError(t, err, "error in IssueSignature")
// }

// func TestFullIssuance(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)
// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)
// 	msg, err := issuer.IssueSignature(commitMsg.U, testAttributes1, nil, nonce2, nil)
// 	assert.NoError(t, err, "error in IssueSignature")
// 	_, err = b.ConstructCredential(msg, testAttributes1)
// 	assert.NoError(t, err, "error in IssueSignature")
// }

// func TestShowingProof(t *testing.T) {
// 	signature, err := SignMessageBlock(testPrivK, testPubK, testAttributes1)
// 	assert.NoError(t, err, "error producing CL signature.")
// 	cred := &Credential{Pk: testPubK, Attributes: testAttributes1, Signature: signature}
// 	disclosed := []int{1, 2}

// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)

// 	proof, err := cred.CreateDisclosureProof(disclosed, nil, false, context, nonce1)
// 	require.NoError(t, err)

// 	assert.True(t, proof.Verify(testPubK, context, nonce1, false), "Proof of disclosure did not verify, whereas it should.")
// }

// func TestCombinedShowingProof(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	issuer1 := NewIssuer(testPrivK1, testPubK1, context)
// 	cred1 := createCredential(t, context, secret, issuer1)

// 	issuer2 := NewIssuer(testPrivK2, testPubK2, context)
// 	cred2 := createCredential(t, context, secret, issuer2)

// 	b1, err := cred1.CreateDisclosureProofBuilder([]int{1, 2}, nil, false)
// 	require.NoError(t, err)
// 	b2, err := cred2.CreateDisclosureProofBuilder([]int{1, 3}, nil, false)
// 	require.NoError(t, err)
// 	builders := ProofBuilderList([]ProofBuilder{b1, b2})
// 	prooflist, err := builders.BuildProofList(context, nonce1, false)
// 	require.NoError(t, err)

// 	assert.True(t, prooflist.Verify([]*gabikeys.PublicKey{issuer1.Pk, issuer2.Pk}, context, nonce1, false, nil), "Prooflist does not verify whereas it should!")
// }

// // A convenience function for initializing big integers from known correct (10
// // base) strings. Use with care, errors are ignored.
// func s2big(s string) (r *big.Int) {
// 	r, _ = new(big.Int).SetString(s, 10)
// 	return
// }

// func TestShowingProofLogged(t *testing.T) {
// 	nonce1 := s2big("356168310758183945030882")
// 	context := s2big("59317469690166962413036802769129097120995929488116634148207386064523180296869")

// 	c := s2big("92405256824458923934294175762399873039847432841647909261385804859937404075570")
// 	A := s2big("66467922530801909191099602528137141713616048447732479189179865050384832390931230033112445547628606292639430708552418462959456337530534055700746138057512598497120682196611341962749384189596253759402224308748002860890211498962735924481685975488607793795169788837476493253297353146422154392391732925567178805607")
// 	eResponse := s2big("44022597110989879399510333540268555303613344906583879371531630680320900347240418258690335759375210734514869637566864349585531295946323809")
// 	vResponse := s2big("26326301830460880582628741955953428491879823201714737915103888193625032953131902593859116395461541557845953939714765660366793552012359281854190756504190064959818584175057775414324351414234450208391534497565506441579960808534266557458251190151268682500197950418141493586125049371381626638554299245282498637246703583102656876690825544275995631773170789236920674341621008537679924624747222821679128060382072191284077393034573357698475000667180794116538132628586533009732462826119381931507809052573496513689222244701991737191273263148163121236326525677935993049602389899306007664212328515456044738278420")

// 	aResponses := map[int]*big.Int{
// 		0: s2big("55247823867049193571627241180110605447453053126985891402640532123848293918217459966028364637387399903283634100097425890971508590427350301193682412170041146212137866279677802531"),
// 	}

// 	aDisclosed := map[int]*big.Int{
// 		1: s2big("1100598411265"),
// 		2: s2big("43098508374675488371040117572049064979183030441504364"),
// 		3: s2big("4919409929397552454"),
// 	}

// 	proof1 := &ProofD{C: c, A: A, EResponse: eResponse, VResponse: vResponse, AResponses: aResponses, ADisclosed: aDisclosed}

// 	assert.True(t, proof1.Verify(testPubK, context, nonce1, false), "Proof of disclosure did not verify, whereas it should.")

// 	aDisclosed[1] = s2big("123")
// 	proof := &ProofD{C: c, A: A, EResponse: eResponse, VResponse: vResponse, AResponses: aResponses, ADisclosed: aDisclosed}
// 	assert.False(t, proof.Verify(testPubK, context, nonce1, false), "Proof of disclosure verifies, whereas it should not.")
// }

// func TestFullIssuanceAndShowing(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	// Issuance
// 	builder, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := builder.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)
// 	issuer := NewIssuer(testPrivK, testPubK, context)
// 	sigMsg, err := issuer.IssueSignature(commitMsg.U, testAttributes1, nil, nonce2, nil)
// 	assert.NoError(t, err, "error in IssueSignature")

// 	cred, err := builder.ConstructCredential(sigMsg, testAttributes1)
// 	assert.NoError(t, err, "error in credential construction")

// 	// Showing
// 	n1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	disclosed := []int{1, 2}

// 	proof, err := cred.CreateDisclosureProof(disclosed, nil, false, context, n1)
// 	require.NoError(t, err)
// 	assert.True(t, proof.Verify(testPubK, context, n1, false), "Proof of disclosure does not verify, whereas it should.")
// }

// func TestFullBoundIssuanceAndShowing(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	// First create a credential
// 	cb1, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := cb1.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer1 := NewIssuer(testPrivK, testPubK, context)
// 	ism, err := issuer1.IssueSignature(commitMsg.U, testAttributes1, nil, nonce2, nil)
// 	assert.NoError(t, err, "error creating Issue Signature")

// 	cred1, err := cb1.ConstructCredential(ism, testAttributes1)
// 	assert.NoError(t, err, "error creating credential")

// 	// Then create another credential based on the same credential with a partial
// 	// disclosure of the first credential.
// 	cb2, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	issuer2 := NewIssuer(testPrivK, testPubK, context)

// 	db, err := cred1.CreateDisclosureProofBuilder([]int{1, 2}, nil, false)
// 	require.NoError(t, err)
// 	builders := ProofBuilderList([]ProofBuilder{db, cb2})
// 	prooflist, err := builders.BuildProofList(context, nonce1, false)
// 	require.NoError(t, err)

// 	commitMsg2 := cb2.CreateIssueCommitmentMessage(prooflist)

// 	assert.True(t, commitMsg2.Proofs.Verify([]*gabikeys.PublicKey{testPubK, testPubK}, context, nonce1, false, nil), "Proofs in commit message do not verify!")

// 	msg, err := issuer2.IssueSignature(commitMsg2.U, testAttributes1, nil, nonce2, nil)
// 	assert.NoError(t, err, "error creating Issue Signature")
// 	cred2, err := cb2.ConstructCredential(msg, testAttributes1)
// 	assert.NoError(t, err, "error creating credential")

// 	// Showing
// 	nonce1s, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	disclosedAttributes := []int{1, 3}
// 	proof, err := cred2.CreateDisclosureProof(disclosedAttributes, nil, false, context, nonce1s)
// 	require.NoError(t, err)
// 	assert.True(t, proof.Verify(testPubK, context, nonce1s, false), "Proof of disclosure did not verify, whereas it should.")
// }

// func TestLegendreSymbol(t *testing.T) {
// 	testValues := []struct {
// 		a, b *big.Int
// 		r    int
// 	}{
// 		{big.NewInt(30), big.NewInt(23), -1},
// 		{big.NewInt(30), big.NewInt(57), 0},
// 		{big.NewInt(28), big.NewInt(55), 1},
// 		{s2big("120567422773271477355736570949008495838563053707948503865496543401556073640359251802074724569581730875929260027496777788057157018774844493782617608416083158200499434405335785459168671686133613000185852866284484792120896546591747003597473925949437927506500843016369829879812643202318141301999974341721061899407"), s2big("10081623199657828324376343366809453358437559295255845251936401190895787407186296178275845571433532607558964794229309528127907617140159040217132395339392137"), -1},
// 		{s2big("105878163698280660110888466652097535916687465611111576106176905877150374138910442768678634516927223961780370321686931770425843416322974676216250417627401183361009783057565157684769110212432099898936413921173832522537816098479555382252890282429726874156063647841447515205988065173539077417577690690964366031827"), s2big("12068480243344717677229417744719977222905953162787318652957714137579792958858463398943120303998730505158703022444367980634366645715971224580814228085805223"), 1},
// 		{testPubK.S, testPrivK.P, 1},
// 		{testPubK.S, testPrivK.Q, 1},
// 	}
// 	for _, tv := range testValues {
// 		s := common.LegendreSymbol(tv.a, tv.b)
// 		assert.Equalf(t, s, tv.r, "Wrong Legendre symbol for (%v, %v). Expected %d, got %v.", tv.a, tv.b, tv.r, s)
// 	}
// }

// func TestGenerateKeyPair(t *testing.T) {
// 	// Insert toy parameters for speed
// 	base := gabikeys.BaseParameters{
// 		LePrime: 120,
// 		Lh:      256,
// 		Lm:      256,
// 		Ln:      256,
// 		Lstatzk: 80,
// 	}
// 	gabikeys.DefaultSystemParameters[256] = &gabikeys.SystemParameters{
// 		BaseParameters:    base,
// 		DerivedParameters: gabikeys.MakeDerivedParameters(base),
// 	}

// 	// Using the toy parameters, generate a bunch of keys
// 	for i := 0; i < 1; i++ {
// 		privk, pubk, err := gabikeys.GenerateKeyPair(gabikeys.DefaultSystemParameters[256], 6, 0, time.Now().AddDate(1, 0, 0))
// 		assert.NoError(t, err, "error generating key pair")
// 		testPrivateKey(t, privk, true)
// 		testPublicKey(t, pubk, privk)
// 	}

// 	// Generate one key of the smallest supported sizes
// 	//privk, pubk, err := keys.GenerateKeyPair(keys.DefaultSystemParameters[1024], 6, 0, time.Now().AddDate(1, 0, 0))
// 	//assert.NoError(t, err, "error generating key pair")
// 	//testPrivateKey(t, privk, true)
// 	//testPublicKey(t, pubk, privk)
// }

// func createKeyshareCredential(t *testing.T, context, secret, keyshareP *big.Int, attrs []*big.Int, issuer *Issuer) *Credential {
// 	// First create a credential
// 	keylength := 1024
// 	nonce1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	cb, err := NewCredentialBuilder(issuer.Pk, context, secret, nonce2, keyshareP, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := cb.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	ism, err := issuer.IssueSignature(commitMsg.U, attrs, nil, nonce2, nil)
// 	assert.NoError(t, err, "error creating Issue Signature")

// 	cred, err := cb.ConstructCredential(ism, attrs)
// 	assert.NoError(t, err, "error creating credential")
// 	return cred
// }

// func createCredential(t *testing.T, context, secret *big.Int, issuer *Issuer) *Credential {
// 	return createKeyshareCredential(t, context, secret, nil, testAttributes1, issuer)
// }

// var squaresTable = rangeproof.GenerateSquaresTable(65535)

// func TestRangeProofGreaterOrEqual(t *testing.T) {
// 	stmt, err := rangeproof.NewStatement(rangeproof.GreaterOrEqual, new(big.Int).Sub(testAttributes1[0], big.NewInt(63)))
// 	assert.NoError(t, err)
// 	testRangeProofs(t, true, []*rangeproof.Statement{stmt})
// }

// func TestRangeProofEqual(t *testing.T) {
// 	stmt, err := rangeproof.NewStatement(rangeproof.GreaterOrEqual, new(big.Int).Set(testAttributes1[0]))
// 	assert.NoError(t, err)
// 	testRangeProofs(t, true, []*rangeproof.Statement{stmt})
// }

// func TestRangeProofLesserOrEqual(t *testing.T) {
// 	stmt, err := rangeproof.NewStatement(rangeproof.LesserOrEqual, new(big.Int).Add(testAttributes1[0], big.NewInt(63)))
// 	assert.NoError(t, err)
// 	testRangeProofs(t, true, []*rangeproof.Statement{stmt})
// }

// func TestRangeProofMultiple(t *testing.T) {
// 	stmt1, err := rangeproof.NewStatement(rangeproof.LesserOrEqual, new(big.Int).Add(testAttributes1[0], big.NewInt(63)))
// 	assert.NoError(t, err)
// 	stmt2, err := rangeproof.NewStatement(rangeproof.GreaterOrEqual, new(big.Int).Sub(testAttributes1[0], big.NewInt(63)))
// 	assert.NoError(t, err)
// 	testRangeProofs(t, true, []*rangeproof.Statement{stmt1, stmt2})
// }

// func TestRangeProofFalseStatement(t *testing.T) {
// 	stmt, err := rangeproof.NewStatement(rangeproof.GreaterOrEqual, new(big.Int).Add(testAttributes1[0], big.NewInt(63)))
// 	assert.NoError(t, err)
// 	testRangeProofs(t, false, []*rangeproof.Statement{stmt})
// }

// func testRangeProofs(t *testing.T, trueStatements bool, statements []*rangeproof.Statement) {
// 	for _, splitter := range []rangeproof.SquareSplitter{nil, squaresTable} {
// 		context, err := common.RandomBigInt(testPubK1.Params.Lh)
// 		assert.NoError(t, err)
// 		nonce, err := common.RandomBigInt(testPubK1.Params.Lstatzk)
// 		assert.NoError(t, err)
// 		secret, err := common.RandomBigInt(testPubK1.Params.Lm)
// 		assert.NoError(t, err)

// 		issuer := NewIssuer(testPrivK1, testPubK1, context)
// 		cred := createCredential(t, context, secret, issuer)

// 		for _, statement := range statements {
// 			statement.Splitter = splitter
// 		}

// 		// prover part: create a disclosure proof
// 		proof, err := cred.CreateDisclosureProof(
// 			[]int{2}, map[int][]*rangeproof.Statement{1: statements}, false, context, nonce,
// 		)

// 		if !trueStatements {
// 			require.Equal(t, rangeproof.ErrFalseStatement, err)
// 			continue
// 		}

// 		// verifier part: verify disclosure proof and check the proven statement
// 		require.NoError(t, err)
// 		assert.True(t, proof.Verify(testPubK1, context, nonce, false))

// 		for i, statement := range statements {
// 			typ, factor, bound := proof.RangeProofs[1][i].ProvenStatement()
// 			assert.Equal(t, statement.Bound, bound)
// 			assert.Equal(t, uint(1), factor)
// 			sign, err := typ.Sign()
// 			assert.NoError(t, err)
// 			assert.Equal(t, statement.Sign, sign)

// 			// The proof proves the statement as is
// 			assert.True(t, proof.RangeProofs[1][i].Proves(statement))

// 			if statement.Sign == 1 {
// 				// If attr >= bound, then also attr >= bound - 1
// 				statement.Bound.Sub(statement.Bound, big.NewInt(1))
// 			} else {
// 				// If attr <= bound, then also attr <= bound + 1
// 				statement.Bound.Add(statement.Bound, big.NewInt(1))
// 			}
// 			assert.True(t, proof.RangeProofs[1][i].Proves(statement))
// 		}
// 	}
// }

// func TestFullBoundIssuanceAndShowingRandomIssuers(t *testing.T) {
// 	keylength := 1024
// 	context, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lh)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lm)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)

// 	// First create a single credential for an issuer
// 	issuer1 := NewIssuer(testPrivK1, testPubK1, context)
// 	cred1 := createCredential(t, context, secret, issuer1)

// 	// Then create another credential based on the same credential with a partial
// 	// disclosure of the first credential.
// 	issuer2 := NewIssuer(testPrivK2, testPubK2, context)
// 	cb2, err := NewCredentialBuilder(issuer2.Pk, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)

// 	nonce1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	db, err := cred1.CreateDisclosureProofBuilder([]int{1, 2}, nil, false)
// 	require.NoError(t, err)
// 	builders := ProofBuilderList([]ProofBuilder{db, cb2})
// 	prooflist, err := builders.BuildProofList(context, nonce1, false)
// 	require.NoError(t, err)

// 	commitMsg := cb2.CreateIssueCommitmentMessage(prooflist)

// 	assert.True(t, commitMsg.Proofs.Verify([]*gabikeys.PublicKey{issuer1.Pk, issuer2.Pk}, context, nonce1, false, nil), "Proofs in commit message do not verify!")

// 	msg, err := issuer2.IssueSignature(commitMsg.U, testAttributes2, nil, nonce2, nil)
// 	assert.NoError(t, err, "error creating Issue Signature")
// 	cred2, err := cb2.ConstructCredential(msg, testAttributes2)
// 	assert.NoError(t, err, "error creating credential")

// 	// Showing
// 	nonce1s, err := common.RandomBigInt(issuer2.Pk.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	disclosedAttributes := []int{1, 3}
// 	proof, err := cred2.CreateDisclosureProof(disclosedAttributes, nil, false, context, nonce1s)
// 	require.NoError(t, err)
// 	assert.True(t, proof.Verify(issuer2.Pk, context, nonce1s, false), "Proof of disclosure did not verify, whereas it should.")
// }

// func TestWronglyBoundIssuanceAndShowingWithDifferentIssuers(t *testing.T) {
// 	keylength := 1024
// 	context, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lh)
// 	assert.NoError(t, err)
// 	// Use two different secrets for the credentials, this should fail eventually
// 	secret1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lm)
// 	assert.NoError(t, err)
// 	secret2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lm)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)

// 	// First create a single credential for an issuer
// 	issuer1 := NewIssuer(testPrivK1, testPubK1, context)
// 	cred1 := createCredential(t, context, secret1, issuer1)

// 	// Then create another credential based on the same credential with a partial
// 	// disclosure of the first credential.
// 	issuer2 := NewIssuer(testPrivK2, testPubK2, context)
// 	cb2, err := NewCredentialBuilder(issuer2.Pk, context, secret2, nonce2, nil, nil)
// 	assert.NoError(t, err)

// 	nonce1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	db, err := cred1.CreateDisclosureProofBuilder([]int{1, 2}, nil, false)
// 	require.NoError(t, err)
// 	builders := ProofBuilderList([]ProofBuilder{db, cb2})
// 	prooflist, err := builders.BuildProofList(context, nonce1, false)
// 	require.NoError(t, err)

// 	commitMsg := cb2.CreateIssueCommitmentMessage(prooflist)

// 	assert.False(t, commitMsg.Proofs.Verify([]*gabikeys.PublicKey{issuer1.Pk, issuer2.Pk}, context, nonce1, false, nil), "Proofs in commit message verify, whereas they should not!")
// }

// func TestBigAttribute(t *testing.T) {
// 	attrs := []*big.Int{
// 		new(big.Int).SetBytes([]byte("one")),
// 		new(big.Int).SetBytes([]byte("two")),
// 		new(big.Int).SetBytes([]byte("This is a very long attribute: its size of 132 bytes exceeds the maximum message length of all currently supported public key sizes.")),
// 	}
// 	signature, err := SignMessageBlock(testPrivK, testPubK, attrs)
// 	assert.NoError(t, err, "error producing CL signature.")
// 	cred := &Credential{Pk: testPubK, Attributes: attrs, Signature: signature}
// 	assert.True(t, signature.Verify(testPubK, attrs), "Failed to create CL signature over large attribute")

// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)

// 	// Don't disclose large attribute
// 	proof, err := cred.CreateDisclosureProof([]int{1}, nil, false, context, nonce1)
// 	require.NoError(t, err)
// 	assert.True(t, proof.Verify(testPubK, context, nonce1, false), "Failed to verify ProofD with large undisclosed attribute")
// 	// Disclose large attribute
// 	proof, err = cred.CreateDisclosureProof([]int{2}, nil, false, context, nonce1)
// 	require.NoError(t, err)
// 	assert.True(t, proof.Verify(testPubK, context, nonce1, false), "Failed to verify ProofD with large undisclosed attribute")
// }

// func setupRevocation(t *testing.T, sk *gabikeys.PrivateKey, pk *gabikeys.PublicKey) (*revocation.Witness, *revocation.Update, *revocation.Accumulator) {
// 	if !sk.RevocationSupported() {
// 		require.NoError(t, gabikeys.GenerateRevocationKeypair(sk, pk))
// 	}

// 	update, err := revocation.NewAccumulator(sk)
// 	require.NoError(t, err)

// 	acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
// 	require.NoError(t, err)

// 	witness, err := revocation.RandomWitness(sk, acc)
// 	require.NoError(t, err)
// 	witness.SignedAccumulator = update.SignedAccumulator
// 	require.Zero(t, new(big.Int).Exp(witness.U, witness.E, pk.N).Cmp(acc.Nu))

// 	return witness, update, acc
// }

// func revocationAttrs(w *revocation.Witness) []*big.Int {
// 	return append(testAttributes1, w.E)
// }

// func TestNotRevoked(t *testing.T) {
// 	witness, _, _ := setupRevocation(t, testPrivK, testPubK)

// 	// Issuance
// 	attrs := revocationAttrs(witness)
// 	signature, err := SignMessageBlock(testPrivK, testPubK, attrs)
// 	require.NoError(t, err)
// 	require.True(t, signature.Verify(testPubK, attrs))

// 	cred := &Credential{
// 		Signature:            signature,
// 		Pk:                   testPubK,
// 		Attributes:           attrs,
// 		NonRevocationWitness: witness,
// 	}
// 	require.NoError(t, cred.NonrevPrepareCache())

// 	// showing
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)

// 	proofd, err := cred.CreateDisclosureProof([]int{1, 2}, nil, true, context, nonce)
// 	require.NoError(t, err)
// 	require.NotNil(t, proofd.NonRevocationProof)
// 	require.True(t, ProofList{proofd}.Verify([]*gabikeys.PublicKey{testPubK}, context, nonce, false, nil))
// }

// func TestRevoked(t *testing.T) {
// 	witness, update, acc := setupRevocation(t, testPrivK, testPubK)

// 	acc, event, err := acc.Remove(testPrivK, witness.E, update.Events[0])
// 	require.NoError(t, err)
// 	update, err = revocation.NewUpdate(testPrivK, acc, []*revocation.Event{event})
// 	require.NoError(t, err)

// 	// Try to update witness to latest update (where the witness.E is removed)
// 	require.Equal(t, revocation.ErrorRevoked, witness.Update(testPubK, update))
// }

// func TestFullIssueAndShowWithRevocation(t *testing.T) {
// 	witness, update, acc := setupRevocation(t, testPrivK, testPubK)

// 	// Issuance
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)
// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, nil)
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)
// 	attrs := revocationAttrs(witness)
// 	msg, err := issuer.IssueSignature(commitMsg.U, attrs, witness, nonce2, nil)
// 	require.NoError(t, err, "error in IssueSignature")
// 	cred, err := b.ConstructCredential(msg, attrs)
// 	require.NoError(t, err, "error in ConstructCredential")

// 	// Showing
// 	nonce1s, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	disclosedAttributes := []int{1, 3}
// 	require.Len(t, cred.nonrevCache, 0)
// 	proofd, err := cred.CreateDisclosureProof(disclosedAttributes, nil, true, context, nonce1s)
// 	require.NoError(t, err)
// 	require.True(t, proofd.HasNonRevocationProof())
// 	assert.True(t, proofd.Verify(testPubK, context, nonce1s, false), "Proof of disclosure did not verify, whereas it should.")

// 	// prepare nonrevocation proof cache
// 	require.NoError(t, cred.NonrevPrepareCache())
// 	require.Len(t, cred.nonrevCache, 1)
// 	cache := <-cred.nonrevCache
// 	require.Equal(t, cache.index, acc.Index)
// 	cred.nonrevCache <- cache

// 	// show again, using the nonrevocation proof cache
// 	proofd, err = cred.CreateDisclosureProof(disclosedAttributes, nil, true, context, nonce1s)
// 	require.NoError(t, err)
// 	require.True(t, proofd.HasNonRevocationProof())
// 	assert.True(t, proofd.Verify(testPubK, context, nonce1s, false), "Proof of disclosure did not verify, whereas it should.")
// 	require.Len(t, cred.nonrevCache, 0)
// 	require.NoError(t, cred.NonrevPrepareCache())

// 	// simulate revocation of another credential
// 	w, err := revocation.RandomWitness(testPrivK, acc)
// 	require.NoError(t, err)
// 	acc, event, err := acc.Remove(testPrivK, w.E, update.Events[0])
// 	require.NoError(t, err)
// 	update, err = revocation.NewUpdate(testPrivK, acc, []*revocation.Event{event})
// 	require.NoError(t, err)

// 	// update witness and nonrevocation proof cache
// 	require.NoError(t, cred.NonRevocationWitness.Update(testPubK, update))
// 	require.NoError(t, cred.NonrevPrepareCache())
// 	require.Len(t, cred.nonrevCache, 1)
// 	cache = <-cred.nonrevCache
// 	require.Equal(t, cache.index, acc.Index)
// }

// func TestKeyshare(t *testing.T) {
// 	secret, err := NewKeyshareSecret()
// 	require.NoError(t, err)

// 	commit, W, err := NewKeyshareCommitments(secret, []*gabikeys.PublicKey{testPubK})
// 	require.NoError(t, err)
// 	require.LessOrEqual(t, uint(commit.BitLen()), gabikeys.DefaultSystemParameters[2048].LmCommit)

// 	response := KeyshareResponseLegacy(secret, commit, big.NewInt(123), testPubK)
// 	assert.Equal(t, new(big.Int).Exp(testPubK.R[0], response.SResponse, testPubK.N),
// 		new(big.Int).Mod(
// 			new(big.Int).Mul(
// 				W[0].Pcommit,
// 				new(big.Int).Exp(W[0].P, big.NewInt(123), testPubK.N)),
// 			testPubK.N))
// }

// // TODO: tests to add:
// // - Reading/writing key files
// // - Tests with expiration dates?

// // --- Random blind issuance tests ---

// func TestRandomBlindProofU(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)
// 	proofU, err := commitMsg.Proofs.GetFirstProofU()
// 	assert.NoError(t, err)

// 	assert.Len(t, proofU.MUserResponses, 1)
// 	assert.Contains(t, proofU.MUserResponses, 2+1)

// 	c, err := proofU.ChallengeContribution(testPubK)
// 	assert.NoError(t, err)
// 	assert.True(t, proofU.VerifyWithChallenge(testPubK, createChallenge(context, nonce1, c, false)))
// }

// // Tests CreateProof() and Commit()
// func TestRandomBlindCreateProofUandCommit(t *testing.T) {
// 	keylength := 1024
// 	context, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[keylength].Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	contributions, err := b.Commit(map[string]*big.Int{"secretkey": secret})
// 	require.NoError(t, err)
// 	proofU := b.CreateProof(createChallenge(context, nonce1, contributions, false))
// 	c, err := proofU.ChallengeContribution(testPubK)
// 	assert.NoError(t, err)
// 	assert.True(t, proofU.VerifyWithChallenge(testPubK, createChallenge(context, nonce1, c, false)), "ProofU does not verify, whereas it should.")
// }

// func TestRandomBlindIssuance(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)

// 	// testAttributes3 = [a0, a1, a2 (nil), a3] becomes
// 	// cred.Attributes = [sk, a0, a1, a2, a3] in the credential, with a2 the sum of two random 255-bit integers.
// 	msg, err := issuer.IssueSignature(commitMsg.U, testAttributes3, nil, nonce2, []int{2})
// 	assert.NoError(t, err, "error in IssueSignature")
// 	require.Len(t, msg.MIssuer, 1)
// 	require.Contains(t, msg.MIssuer, 3)

// 	cred, err := b.ConstructCredential(msg, testAttributes3)
// 	assert.NoError(t, err, "error in ConstructCredential")
// 	assert.NotNil(t, cred.Attributes[3], "randomblind should not be nil")

// 	// Test if 0 <= randomblind < 2^256
// 	assert.Equal(t, 1, cred.Attributes[3].Cmp(big.NewInt(-1)))
// 	assert.Equal(t, -1, cred.Attributes[3].Cmp(new(big.Int).Lsh(big.NewInt(1), 256)))
// }

// func TestRandomBlindIssuanceTooFewAttributes(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)

// 	// testAttributes3 = [a0, a1, a2 (nil), a3] becomes
// 	// cred.Attributes = [sk, a0, a1, a2, a3] in the credential, with a2 the sum of two random 255-bit integers.
// 	msg, err := issuer.IssueSignature(commitMsg.U, testAttributes3, nil, nonce2, []int{2})
// 	assert.NoError(t, err, "error in IssueSignature")
// 	// The following line should fail because we don't give enough values for all non-randomblind attributes
// 	// We give 2, but we need 3 (for a0, a1 and a3)
// 	_, err = b.ConstructCredential(msg, testAttributes3[:1])
// 	assert.EqualError(t, err, "got too few attributes")
// }

// func TestMultipleRandomBlindIssuance(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{1, 2, 3})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)

// 	// testAttributes4 = [a0, a1 (nil), a2 (nil), a3 (nil)] becomes
// 	// cred.Attributes = [sk, a0, a1, a2, a3] in the credential,
// 	// with a1, a2, a3 the sum of two random 255-bit integers.
// 	msg, err := issuer.IssueSignature(commitMsg.U, testAttributes4, nil, nonce2, []int{1, 2, 3})
// 	assert.NoError(t, err, "error in IssueSignature")

// 	cred, err := b.ConstructCredential(msg, testAttributes4)
// 	assert.NoError(t, err, "error in ConstructCredential")

// 	for _, i := range []int{2, 3, 4} {
// 		assert.Contains(t, msg.MIssuer, i)
// 		assert.NotNil(t, cred.Attributes[i], "randomblind attribute should not be nil after issuance")
// 		// Test 0 <= randomblind < 2^256
// 		assert.Equal(t, 1, cred.Attributes[i].Cmp(big.NewInt(-1)))
// 		assert.Equal(t, -1, cred.Attributes[i].Cmp(new(big.Int).Lsh(big.NewInt(1), 256)))
// 	}
// }

// func TestIssueSignatureNonZeroRandomBlindAttributes(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)

// 	// testAttributes1 = [a0, a1, a2, a3] (all non-nil)
// 	_, err = issuer.IssueSignature(commitMsg.U, testAttributes1, nil, nonce2, []int{2})

// 	// The caller of IssueSignature is responsible for initializing the attributes at
// 	// the random blind indices as nil, which was not done in this case, so we expect an error.
// 	assert.EqualError(t, err, "attribute at random blind index should be nil before issuance")
// }

// func TestConstructCredentialNonZeroRandomBlindAttributes(t *testing.T) {
// 	context, err := common.RandomBigInt(testPubK.Params.Lh)
// 	assert.NoError(t, err)
// 	nonce1, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	nonce2, err := common.RandomBigInt(testPubK.Params.Lstatzk)
// 	assert.NoError(t, err)
// 	secret, err := common.RandomBigInt(testPubK.Params.Lm)
// 	assert.NoError(t, err)

// 	b, err := NewCredentialBuilder(testPubK, context, secret, nonce2, nil, []int{2})
// 	assert.NoError(t, err)
// 	commitMsg, err := b.CommitToSecretAndProve(nonce1)
// 	assert.NoError(t, err)

// 	issuer := NewIssuer(testPrivK, testPubK, context)

// 	// testAttributes3 = [a0, a1, a2 (nil), a3]
// 	msg, err := issuer.IssueSignature(commitMsg.U, testAttributes3, nil, nonce2, []int{2})
// 	assert.NoError(t, err, "error in IssueSignature")

// 	// testAttributes1 are all non-nil, this should give an error
// 	// attributes at the randomblind indices should be initialized as nil by the client.
// 	_, err = b.ConstructCredential(msg, testAttributes1)
// 	assert.EqualError(t, err, "attribute at random blind index should be nil before issuance")
// }

// func TestKeyshareResponse(t *testing.T) {
// 	// Setup secrets and randomizer
// 	kssSecret, err := GenerateSecretAttribute()
// 	require.NoError(t, err)
// 	userSecret, err := GenerateSecretAttribute()
// 	require.NoError(t, err)

// 	statement, err := rangeproof.NewStatement(rangeproof.GreaterOrEqual, big.NewInt(1))
// 	require.NoError(t, err)
// 	rangeStatements := map[int][]*rangeproof.Statement{
// 		2: {statement},
// 	}

// 	tests := map[string]struct {
// 		builders  ProofBuilderList
// 		signature bool
// 	}{
// 		"Disclosure": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil)},
// 		},
// 		"DisclosureRevocation": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), true, nil),
// 		}},
// 		"DisclosureRangeProof": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, rangeStatements),
// 		}},
// 		"DisclosureRevocationRangeProof": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), true, rangeStatements),
// 		}},
// 		"DoubleDisclosureSameKeys": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 		}},
// 		"DoubleDisclosureDistinctKeys": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, nil),
// 		}},
// 		"DoubleDisclosureRevocation": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), true, nil),
// 		}},
// 		"DoubleDisclosureMixed": {builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 		}},
// 		"Signature": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil)},
// 		},
// 		"SignatureRevocation": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), true, nil),
// 		}},
// 		"SignatureRangeProof": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, rangeStatements),
// 		}},
// 		"SignatureRevocationRangeProof": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), true, rangeStatements),
// 		}},
// 		"DoubleSignatureSameKeys": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 		}},
// 		"DoubleSignatureDistinctKeys": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, nil),
// 		}},
// 		"DoubleSignatureRevocation": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), true, nil),
// 		}},
// 		"DoubleSignatureMixed": {signature: true, builders: ProofBuilderList{
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 		}},
// 		"Issuance": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 		}},
// 		"IssuanceRandomblind": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), []int{2}),
// 		}},
// 		"DoubleIssuanceSameKeys": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 		}},
// 		"DoubleIssuanceDistinctKeys": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newCredBuilder(t, testPubK1, userSecret, kssP(kssSecret, testPubK1), nil),
// 		}},
// 		"DoubleIssuanceRandomblind": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newCredBuilder(t, testPubK1, userSecret, kssP(kssSecret, testPubK1), []int{2}),
// 		}},
// 		"DoubleIssuanceMixed": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newCredBuilder(t, testPubK2, userSecret, nil, nil),
// 		}},
// 		"IssuanceAndDisclosureSameKeys": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 		}},
// 		"IssuanceAndDisclosureDistinctKeys": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, nil),
// 		}},
// 		"IssuanceAndDisclosureRevocation": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), true, nil),
// 		}},
// 		"IssuanceAndDisclosureMixed": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 		}},
// 		"IssuanceAndDisclosureSameAndDisclosureMixed": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK, testPubK, userSecret, kssP(kssSecret, testPubK), false, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 		}},
// 		"IssuanceAndDisclosureMixedAndDisclosureMixed": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 		}},
// 		"Everything": {builders: ProofBuilderList{
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), nil),
// 			newCredBuilder(t, testPubK, userSecret, kssP(kssSecret, testPubK), []int{2}),
// 			newCredBuilder(t, testPubK1, userSecret, kssP(kssSecret, testPubK1), nil),
// 			newCredBuilder(t, testPubK1, userSecret, kssP(kssSecret, testPubK1), []int{2}),
// 			newCredBuilder(t, testPubK2, userSecret, nil, nil),
// 			newCredBuilder(t, testPubK2, userSecret, nil, []int{2}),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), true, nil),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), false, rangeStatements),
// 			newDisclosureBuilder(t, testPrivK1, testPubK1, userSecret, kssP(kssSecret, testPubK1), true, rangeStatements),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, true, nil),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, false, rangeStatements),
// 			newDisclosureBuilder(t, testPrivK2, testPubK2, userSecret, nil, true, rangeStatements),
// 		}},
// 	}

// 	// Perform keyshare protocol for these keys
// 	keys := map[string]*gabikeys.PublicKey{"testPubK": testPubK, "testPubK1": testPubK1}

// 	for testname, testcase := range tests {
// 		t.Run(testname, func(t *testing.T) {
// 			testNewKeyshareResponse(t, keys, kssSecret, userSecret, testcase.builders, testcase.signature)
// 		})
// 	}
// }

// func testNewKeyshareResponse(
// 	t *testing.T,
// 	keys map[string]*gabikeys.PublicKey, // the keys for which the keyshare protocol is done
// 	kssSecret, userSecret *big.Int,
// 	builders ProofBuilderList,
// 	signature bool,
// ) {
// 	// Prepare some vars used throughout the test.
// 	// We use keyNames below to keep track of the builders for which we need to do the keyshare
// 	// protocol, as opposed to those for which we don't: if the index i of the i'th builder is in
// 	// keyNames, we do the protocol, otherwise we don't.
// 	keyNames := map[int]*string{}
// 	var keysSlice []*gabikeys.PublicKey
// 	for i, b := range builders {
// 		keysSlice = append(keysSlice, b.PublicKey())
// 		keyname := b.PublicKey().Issuer
// 		if pk := keys[keyname]; pk != nil {
// 			keyNames[i] = &pk.Issuer
// 		}
// 	}
// 	nonce, err := GenerateNonce()
// 	require.NoError(t, err)

// 	// User chooses randomizer, computes h_W, and sends that to the KSS
// 	userRandomizer, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].LmCommit)
// 	require.NoError(t, err)
// 	randomizers := map[string]*big.Int{"secretkey": userRandomizer}
// 	commRequest, hashInput, err := KeyshareUserCommitmentRequest(builders, randomizers, keys)
// 	require.NoError(t, err)

// 	// The KSS responds with its commitments
// 	kssRandomizer, kssComm, err := NewKeyshareCommitments(kssSecret, keysSlice)
// 	require.NoError(t, err)

// 	// User processes keyshare server commitment into the builders
// 	for i, builder := range builders {
// 		if keyNames[i] != nil {
// 			builder.SetProofPCommitment(kssComm[i])
// 		}
// 	}

// 	// User computes challenge and user response
// 	responseRequest, challenge, err := KeyshareUserResponseRequest(builders, randomizers, hashInput, context, nonce, signature)
// 	require.NoError(t, err)

// 	// User requests keyshare response
// 	proofP, err := KeyshareResponse(kssSecret, kssRandomizer, commRequest, responseRequest, keys)
// 	require.NoError(t, err)
// 	require.Equal(t, challenge, proofP.C)

// 	// Manually verify the proof of knowledge over the total secret
// 	lhs := new(big.Int)
// 	lhs.Exp(testPubK.R[0], proofP.SResponse, testPubK.N)
// 	totalP := new(big.Int)
// 	totalP.Exp(testPubK.R[0], new(big.Int).Add(kssSecret, userSecret), testPubK.N)
// 	totalComm := new(big.Int)
// 	totalComm.Mul(new(big.Int).Exp(testPubK.R[0], userRandomizer, testPubK.N), kssComm[0].Pcommit).Mod(totalComm, testPubK.N)
// 	rhs := new(big.Int)
// 	rhs.Mul(new(big.Int).Exp(totalP, challenge, testPubK.N), totalComm).Mod(rhs, testPubK.N)
// 	require.Equal(t, 0, rhs.Cmp(lhs))

// 	// Build and verify the proofs
// 	proofPs := make([]*ProofP, len(builders))
// 	var kss []string // specifies to Verify() below which proof uses which keyshare server
// 	for i := range builders {
// 		if keyNames[i] == nil {
// 			kss = append(kss, "")
// 		} else {
// 			proofPs[i] = proofP
// 			kss = append(kss, "keyshare server")
// 		}
// 	}
// 	proofs, err := builders.BuildDistributedProofList(challenge, proofPs)
// 	require.NoError(t, err)
// 	require.True(t, proofs.Verify(keysSlice, context, nonce, signature, kss))

// 	// In case of issuance, check that we can construct valid credentials
// 	privkeys := map[string]*gabikeys.PrivateKey{
// 		"testPubK": testPrivK, "testPubK1": testPrivK1, "testPubK2": testPrivK2,
// 	}
// 	for i, proof := range proofs {
// 		if proofU, ok := proof.(*ProofU); ok {
// 			builder := builders[i].(*CredentialBuilder)
// 			issuer := NewIssuer(privkeys[builder.pk.Issuer], builder.pk, context)
// 			attrs := slices.Clone(testAttributes1)
// 			var randomblind []int
// 			for i := range proofU.MUserResponses {
// 				randomblind = append(randomblind, i-1)
// 				attrs[i-1] = nil
// 			}
// 			ism, err := issuer.IssueSignature(proofU.U, attrs, nil, builder.nonce2, randomblind)
// 			require.NoError(t, err, "error creating Issue Signature")
// 			cred, err := builder.ConstructCredential(ism, attrs)
// 			require.NoError(t, err, "error creating credential")
// 			cred.Signature.Verify(builder.pk, cred.Attributes)
// 		}
// 	}
// }

// var context = bigOne

// func newCredBuilder(t *testing.T, pk *gabikeys.PublicKey, secret, kssP *big.Int, randomblind []int) *CredentialBuilder {
// 	nonce2, err := common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lstatzk)
// 	require.NoError(t, err)
// 	credBuilder, err := NewCredentialBuilder(pk, context, secret, nonce2, kssP, randomblind)
// 	require.NoError(t, err)
// 	return credBuilder
// }

// func newDisclosureBuilder(t *testing.T,
// 	sk *gabikeys.PrivateKey,
// 	pk *gabikeys.PublicKey,
// 	secret *big.Int,
// 	kssP *big.Int,
// 	rev bool,
// 	rangeStatements map[int][]*rangeproof.Statement,
// ) *DisclosureProofBuilder {
// 	var witness *revocation.Witness
// 	attrs := testAttributes1
// 	if rev {
// 		witness, _, _ = setupRevocation(t, sk, pk)
// 		attrs = append(testAttributes1, witness.E)
// 	}

// 	cred := createKeyshareCredential(t, context, secret, kssP, attrs, NewIssuer(sk, pk, context))
// 	cred.NonRevocationWitness = witness
// 	require.True(t, cred.Signature.Verify(pk, cred.Attributes))

// 	if rev {
// 		require.NoError(t, cred.NonrevPrepareCache())
// 		require.NoError(t, cred.NonRevocationWitness.Verify(pk))
// 	}

// 	disclosureBuilder, err := cred.CreateDisclosureProofBuilder([]int{1}, rangeStatements, rev)
// 	require.NoError(t, err)
// 	return disclosureBuilder
// }

// func kssP(kssSecret *big.Int, pk *gabikeys.PublicKey) *big.Int {
// 	return new(big.Int).Exp(pk.R[0], kssSecret, pk.N)
// }

// func TestKeyshareResponseSingleBase(t *testing.T) {
// 	kssSecret, err := GenerateSecretAttribute()
// 	require.NoError(t, err)
// 	userSecret, err := GenerateSecretAttribute()
// 	require.NoError(t, err)

// 	nonce, err := GenerateNonce()
// 	require.NoError(t, err)

// 	keysSlice := []*gabikeys.PublicKey{testPubK}
// 	keysMap := map[string]*gabikeys.PublicKey{"testPubK": testPubK}

// 	kssRandomizer, kssComm, err := NewKeyshareCommitments(kssSecret, keysSlice)
// 	require.NoError(t, err)
// 	userRandomizer, userComm, err := NewKeyshareCommitments(userSecret, keysSlice)
// 	require.NoError(t, err)

// 	totalP := new(big.Int)
// 	totalP.Mul(userComm[0].P, kssComm[0].P).Mod(totalP, testPubK.N)
// 	totalW := new(big.Int)
// 	totalW.Mul(userComm[0].Pcommit, kssComm[0].Pcommit).Mod(totalW, testPubK.N)

// 	keyID := "testPubK"
// 	hashedComm, err := keyshareUserCommitmentsHash([]KeyshareUserChallengeInput[string]{{
// 		KeyID:      &keyID,
// 		Value:      totalP,
// 		Commitment: userComm[0].Pcommit,
// 	}})
// 	require.NoError(t, err)

// 	challenge := createChallenge(bigOne, nonce, []*big.Int{totalP, totalW}, false)

// 	commRequest := KeyshareCommitmentRequest{HashedUserCommitments: hashedComm}
// 	responseRequest := KeyshareResponseRequest[string]{
// 		Nonce:              nonce,
// 		UserResponse:       new(big.Int).Add(userRandomizer, new(big.Int).Mul(challenge, userSecret)),
// 		IsSignatureSession: false,
// 		UserChallengeInput: []KeyshareUserChallengeInput[string]{{
// 			KeyID:      &keyID,
// 			Value:      totalP,
// 			Commitment: userComm[0].Pcommit,
// 		}},
// 	}

// 	response, err := KeyshareResponse(kssSecret, kssRandomizer, commRequest, responseRequest, keysMap)
// 	require.NoError(t, err)

// 	lhs := new(big.Int).Exp(testPubK.R[0], response.SResponse, testPubK.N)
// 	rhs := new(big.Int)
// 	rhs.Mul(new(big.Int).Exp(totalP, challenge, testPubK.N), totalW).Mod(rhs, testPubK.N)

// 	require.Equal(t, 0, lhs.Cmp(rhs))
// }

func TestMain(m *testing.M) {
	err := setupParameters()
	if err != nil {
		if e, ok := err.(*errors.Error); ok {
			fmt.Println(string(e.Stack()))
		}
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestEverything(test *testing.T) {
	Test()
}
