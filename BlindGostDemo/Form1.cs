using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;

namespace BlindGostDemo
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private SecureRandom random;
        private FpCurve curve;
        private ECDomainParameters parameters;
        private BigInteger mod_p;

        private void Init()
        {
            random = new SecureRandom();

            mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p

            curve = new FpCurve(
                mod_p, // p
                new BigInteger("7"), // a
                new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b

            parameters = new ECDomainParameters(
                        curve,
                        new FpPoint(curve,
                        new FpFieldElement(mod_p, new BigInteger("2")), // x
                        new FpFieldElement(mod_p, new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
                        new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

            string message = "Бюллетень";
            tbH.Text = GetDigest(System.Text.Encoding.Default.GetBytes(message)).ToString(16);
            //tbH.Text = (new BigInteger("20798893674476452017134061561508270130637142515379653289952617252661468872421")).ToString(16);
        }

        public BigInteger GetDigest(byte[] message)
        {
            Gost3411Digest gost3411Digest = new Gost3411Digest();
            gost3411Digest.BlockUpdate(message, 0, message.Length);
            byte[] hashmessage = new byte[gost3411Digest.GetDigestSize()];
            gost3411Digest.DoFinal(hashmessage, 0);
            return new BigInteger(hashmessage);
        }


        private BigInteger TextBoxToBigInteger16(TextBox tb)
        {
            return new BigInteger(tb.Text, 16);
        }

        private void button1_Click(object sender, EventArgs e)
        {


            ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(parameters, random);

            ECKeyPairGenerator keygenerator = new ECKeyPairGenerator("ECGOST3410");
            keygenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair pair = keygenerator.GenerateKeyPair();

            ECPrivateKeyParameters validatorPrivate = (ECPrivateKeyParameters)pair.Private;
            ECPublicKeyParameters validatorPublic = (ECPublicKeyParameters)pair.Public;

            /*validatorPrivate = new ECPrivateKeyParameters(
                "ECGOST3410",
                new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
                parameters);

            validatorPublic = new ECPublicKeyParameters(
                "ECGOST3410",
                new FpPoint(curve,
                new FpFieldElement(mod_p, new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403")), // x
                new FpFieldElement(mod_p, new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994"))), // y
                parameters);
            */


            tbValPrivate.Text = validatorPrivate.D.ToString(16);
            tbValPublicX.Text = validatorPublic.Q.X.ToBigInteger().ToString(16);
            tbValPublicY.Text = validatorPublic.Q.Y.ToBigInteger().ToString(16);


        }

        private void button2_Click(object sender, EventArgs ea)
        {
            ECGost3410Signer signer = new ECGost3410Signer();

            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                "ECGOST3410",
                new FpPoint(curve,
                new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicX)), // x
                new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicY))), // y
                parameters);

            BigInteger H = TextBoxToBigInteger16(tbH);
            BigInteger rs = TextBoxToBigInteger16(tbrs);
            BigInteger ss = TextBoxToBigInteger16(tbss);
            BigInteger q = parameters.N;

            //FpPoint G = (FpPoint)parameters.G;
            //FpPoint Q = new FpPoint(curve, new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicX)), new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicY)));
            
            BigInteger e = H.Mod(q);
            byte[] ee = e.ToByteArray();
            byte[] message = H.ToByteArray();
            Array.Reverse(message);

            signer.Init(false, pubKey);

            MessageBox.Show(signer.VerifySignature(message, rs, ss).ToString(), "Проверка подписи");

            //FpPoint C = (FpPoint)(G.Multiply(e.ModInverse(q).Multiply(ss).Mod(q)).Subtract(Q.Multiply(e.ModInverse(q).Multiply(rs).Mod(q))));
            //BigInteger x = C.X.ToBigInteger();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            FpPoint G = (FpPoint)parameters.G;
            BigInteger k = (new BigInteger(random.Next(1, parameters.N.BitCount - 1), random)).Add(BigInteger.One);

            tbk.Text = k.ToString(16);
            FpPoint C = (FpPoint)G.Multiply(k);
            tbCX.Text = C.X.ToBigInteger().ToString(16);
            tbCY.Text = C.Y.ToBigInteger().ToString(16);

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            
            Init();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            BigInteger mu = (new BigInteger(random.Next(1, parameters.N.BitCount - 1), random)).Add(BigInteger.One);
            BigInteger epsilon = (new BigInteger(random.Next(1, parameters.N.BitCount - 1), random)).Add(BigInteger.One);
            BigInteger delta = (new BigInteger(random.Next(1, parameters.N.BitCount - 1), random)).Add(BigInteger.One);
            BigInteger tau = (new BigInteger(random.Next(1, parameters.N.BitCount - 1), random)).Add(BigInteger.One);
            tbVoterMu.Text = mu.ToString(16);
            tbVoterEpsilon.Text = epsilon.ToString(16);
            tbVoterDelta.Text = delta.ToString(16);
            tbVoterTau.Text = tau.ToString(16);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            FpPoint G = (FpPoint)parameters.G;
            FpPoint Q = new FpPoint(curve, new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicX)), new FpFieldElement(mod_p, TextBoxToBigInteger16(tbValPublicY)));
            FpPoint C = new FpPoint(curve, new FpFieldElement(mod_p, TextBoxToBigInteger16(tbCX)), new FpFieldElement(mod_p, TextBoxToBigInteger16(tbCY)));
            BigInteger mu = TextBoxToBigInteger16(tbVoterMu);
            BigInteger epsilon = TextBoxToBigInteger16(tbVoterEpsilon);
            BigInteger delta = TextBoxToBigInteger16(tbVoterDelta);
            BigInteger tau = TextBoxToBigInteger16(tbVoterTau);
            BigInteger q = parameters.N;

            FpPoint Cs = (FpPoint)G.Multiply(epsilon).Add(Q.Multiply(mu)).Add(C.Multiply(delta.ModInverse(q)));
            tbCsX.Text = Cs.X.ToBigInteger().ToString(16);
            tbCsY.Text = Cs.Y.ToBigInteger().ToString(16);
        }

        private void button6_Click(object sender, EventArgs ea)
        {
            BigInteger H = TextBoxToBigInteger16(tbH);
            BigInteger q = parameters.N;
            BigInteger mu = TextBoxToBigInteger16(tbVoterMu);
            BigInteger delta = TextBoxToBigInteger16(tbVoterDelta);
            BigInteger tau = TextBoxToBigInteger16(tbVoterTau);
            BigInteger csx = TextBoxToBigInteger16(tbCsX);

            BigInteger rs = csx.Mod(q);
            BigInteger es = H.Mod(q);
            BigInteger r = (tau.Multiply(delta).Multiply(rs.Add(mu.Multiply(es)))).Mod(q);
            BigInteger e = (es.Multiply(tau)).Mod(q);

            tbrs.Text = rs.ToString(16);
            tbr.Text = r.ToString(16);
            tbes.Text = es.ToString(16);
            tbe.Text = e.ToString(16);
        }

        private void button7_Click(object sender, EventArgs ea)
        {
            BigInteger k = TextBoxToBigInteger16(tbk);
            BigInteger e = TextBoxToBigInteger16(tbe);
            BigInteger d = TextBoxToBigInteger16(tbValPrivate);
            BigInteger r = TextBoxToBigInteger16(tbr);
            BigInteger q = parameters.N;

            BigInteger s = (k.Multiply(e).Add(d.Multiply(r))).Mod(q);

            tbs.Text = s.ToString(16);
        }

        private void button8_Click(object sender, EventArgs e)
        {
            BigInteger epsilon = TextBoxToBigInteger16(tbVoterEpsilon);
            BigInteger delta = TextBoxToBigInteger16(tbVoterDelta);
            BigInteger tau = TextBoxToBigInteger16(tbVoterTau);
            BigInteger s = TextBoxToBigInteger16(tbs);
            BigInteger es = TextBoxToBigInteger16(tbes);
            BigInteger q = parameters.N;

            BigInteger ss = (s.Multiply(delta.ModInverse(q)).Multiply(tau.ModInverse(q)).Mod(q).Add(epsilon.Multiply(es).Mod(q))).Mod(q);

            tbss.Text = ss.ToString(16);
        }

   }
}
