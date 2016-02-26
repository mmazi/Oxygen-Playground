package si.mazi.oxygen;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.params.MainNetParams;
import org.ethereum.crypto.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.util.List;

public class Bip32 {

    private static final Logger log = LoggerFactory.getLogger(Bip32.class);

    private static final MainNetParams MAINNET = MainNetParams.get();

    public static void main(String[] args) {
        DeterministicKey m = HDKeyDerivation.createMasterPrivateKey(Hex.decode("e16e395b7b6c8914903a216d09e470440ee685338a6ae784dd4890c7a184ee57"));

        writeSeed("Master", m);

        writeSeedDerived("User deposits", m, 0);

        writeAccountAddress("Hot wallet - user deposits forward address", m, 1, 0);
        writeAccountAddress("Hot wallet - refills from cold wallet", m, 1, 1);
        writeAccountAddress("Cold wallet", m, 2, 0);
    }

    private static void writeSeed(String keyDesc, DeterministicKey key) {
        log.info(keyDesc + ":");
        log.info("    private: " + key.serializePrivB58(MAINNET));
        log.info("     public: " + key.serializePubB58(MAINNET));
    }

    private static void writeSeedDerived(String keyDesc, DeterministicKey m, int account) {
        writeSeed(keyDesc, deriveAccountExt(m, account));
    }

    private static void writeAccountAddress(String keyDesc, DeterministicKey m, int account, int subIdx) {
        DeterministicKey key = deriveAccountExtSub(m, account, subIdx);
        log.info(keyDesc + ":");
        log.info("        key: " + key.getPrivateKeyAsHex());
        log.info("    address: " + getEthereumAddress(key));
    }

    private static DeterministicKey deriveAccountExtSub(DeterministicKey m, int account, int addressIdx) {
        //  m/44'/60'/account'/0/addressIdx;
        List<ChildNumber> path =
                ImmutableList.of(new ChildNumber(44, true), new ChildNumber(60, true), new ChildNumber(account, true), new ChildNumber(0, false),
                                 new ChildNumber(addressIdx, false));
        return derive(m, path);
    }

    private static DeterministicKey deriveAccountExt(DeterministicKey m, int account) {
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
