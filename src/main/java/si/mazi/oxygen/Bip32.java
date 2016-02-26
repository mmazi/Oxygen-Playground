package si.mazi.oxygen;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.params.MainNetParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.util.Arrays;

public class Bip32 {

    private static final Logger log = LoggerFactory.getLogger(Bip32.class);

    public static final String MASTER =
            "xprv9s21ZrQH143K2f2DCtydaTP9iE1uZF4bFK7L8m6Lrceqi8Ejo1kBrBNUaQYgtHR9QD36CESdDyRSkMrmtriET94kR3auY64K8S4Kigcnzsz";

    public static final MainNetParams MAINNET = MainNetParams.get();

    public static void main(String[] args) {
        DeterministicKey m = DeterministicKey.deserializeB58(MASTER, MAINNET);

        // derive m/44'/60'/0'/0
        DeterministicKey userDepositsExtKey = HDKeyDerivation.deriveChildKey(m.derive(44).derive(60).derive(0), ChildNumber.ZERO);

        log.info("userDepositsExtKey = {}", userDepositsExtKey.serializePubB58(MAINNET));

        for (Integer i : Arrays.asList(100000000, 123456789, 999999999)) {
            DeterministicKey userKey = HDKeyDerivation.deriveChildKey(userDepositsExtKey, new ChildNumber(i));
            log.info("{}", new String(Hex.encode(userKey.getPrivKeyBytes())));
        }
    }
}
