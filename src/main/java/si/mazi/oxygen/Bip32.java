package si.mazi.oxygen;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.params.MainNetParams;
import org.ethereum.crypto.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.util.List;

public class Bip32 {

    private static final Logger log = LoggerFactory.getLogger(Bip32.class);

    private static final MainNetParams MAINNET = MainNetParams.get();

    public static void main(String[] args) throws Exception {
        byte[] masterEntropy = Hex.decode("ed1fca83d319615dd0eed49576db10d21f05a7ea6d461516f5804dc2c1316372");
        byte[] masterSeed = writeMasterMnemonicAndReturnSeed(masterEntropy);
        for (byte b : masterSeed) {
            System.out.print(String.format("%02X", b));
        }
        System.out.println();

        DeterministicKey m = HDKeyDerivation.createMasterPrivateKey(masterSeed);

        writeSeed("Master", m);

        writeSeedDerived("userDeposits", m, 0);
        writeSeedDerived("hotWallet", m, 1);
        writeSeedDerived("coldWallet", m, 2);
        writeSeed("User deposits external chain", deriveAccountExternal(m, 0));

        writeAccountAddress("Hot wallet", m, 1, 0);
        writeAccountAddress("Cold wallet", m, 2, 0);

        //writeAccountAddress("User 123456789 deposits", m, 0, 123456789);
        //writeAccountAddress("User 123456781 deposits", m, 0, 123456781);
        //writeAccountAddress("User 123454321 deposits", m, 0, 123454321);
    }

    private static byte[] writeMasterMnemonicAndReturnSeed(byte[] entropy) throws MnemonicException.MnemonicLengthException {
        List<String> words = MnemonicCode.INSTANCE.toMnemonic(entropy);
        log.info("{}", Joiner.on(' ').join(words));
        return MnemonicCode.toSeed(words, "");
    }

    private static void writeSeed(String keyDesc, DeterministicKey key) {
        log.info(keyDesc + ":");
        log.info("    xprv: " + key.serializePrivB58(MAINNET));
        log.info("    xpub: " + key.serializePubB58(MAINNET));
    }

    private static void writeSeedDerived(String keyDesc, DeterministicKey m, int account) {
        writeSeed(keyDesc, deriveAccount(m, account));
    }

    private static void writeAccountAddress(String keyDesc, DeterministicKey m, int account, int subIdx) {
        DeterministicKey key = deriveAccountExtSub(m, account, subIdx);
        log.info(keyDesc + ":");
        //log.info("        key: " + key.getPrivateKeyAsHex());
        log.info("    address: " + getEthereumAddress(key));
    }

    private static DeterministicKey deriveAccountExtSub(DeterministicKey m, int account, int addressIdx) {
        //  m/44'/60'/account'/0/addressIdx;
        List<ChildNumber> path =
                ImmutableList.of(new ChildNumber(44, true), new ChildNumber(60, true), new ChildNumber(account, true), new ChildNumber(0, false),
                                 new ChildNumber(addressIdx, false));
        return derive(m, path);
    }

    private static DeterministicKey deriveAccount(DeterministicKey m, int account) {
        //  m/44'/60'/account'
        List<ChildNumber> path =
                ImmutableList.of(new ChildNumber(44, true), new ChildNumber(60, true), new ChildNumber(account, true));
        return derive(m, path);
    }

    private static DeterministicKey deriveAccountExternal(DeterministicKey m, int account) {
        //  m/44'/60'/account'/0
        List<ChildNumber> path =
                ImmutableList.of(new ChildNumber(44, true), new ChildNumber(60, true), new ChildNumber(account, true), new ChildNumber(0, false));
        return derive(m, path);
    }

    private static DeterministicKey derive(DeterministicKey m, List<ChildNumber> path) {
        log.debug("Path: m/{}", Joiner.on("/").join(path).replace('H', '\''));
        return new DeterministicHierarchy(m).get(path, false, true);
    }

    private static String getEthereumAddress(DeterministicKey key) {
        return "0x" + Hex.toHexString(new ECKey(null, key.getPubKeyPoint()).getAddress());
    }
}
