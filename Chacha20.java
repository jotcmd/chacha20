/**
 * chacha20 - 256 bits
 * <p/>
 * translation from javascript version:
 * https://github.com/quartzjer/chacha20/blob/master/chacha20.js
 * <p/>
 * Created by jot on 25/5/15.
 */
public class Chacha20 {

    private int[] input = new int[16];

    private static int U8TO32_LE(char[] x, int i) {
        return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
    }

    private static void U32TO8_LE(int[] x, int i, int u) {
        x[i] = u;
        u >>>= 8;
        x[i + 1] = u;
        u >>>= 8;
        x[i + 2] = u;
        u >>>= 8;
        x[i + 3] = u;
    }

    private static int ROTATE(int v, int c) {
        return (v << c) | (v >>> (32 - c));
    }

    public Chacha20(char[] key, char[] nonce, int counter) {
        // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
        this.input[0] = 1634760805;
        this.input[1] = 857760878;
        this.input[2] = 2036477234;
        this.input[3] = 1797285236;
        this.input[4] = U8TO32_LE(key, 0);
        this.input[5] = U8TO32_LE(key, 4);
        this.input[6] = U8TO32_LE(key, 8);
        this.input[7] = U8TO32_LE(key, 12);
        this.input[8] = U8TO32_LE(key, 16);
        this.input[9] = U8TO32_LE(key, 20);
        this.input[10] = U8TO32_LE(key, 24);
        this.input[11] = U8TO32_LE(key, 28);
        // be compatible with the reference ChaCha depending on the nonce size
        if (nonce.length == 12) {
            this.input[12] = counter;
            this.input[13] = U8TO32_LE(nonce, 0);
            this.input[14] = U8TO32_LE(nonce, 4);
            this.input[15] = U8TO32_LE(nonce, 8);
        } else {
            this.input[12] = counter;
            this.input[13] = 0;
            this.input[14] = U8TO32_LE(nonce, 0);
            this.input[15] = U8TO32_LE(nonce, 4);

        }
    }

    private void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 7);
    }

    public void encrypt(char[] dst, char[] src, int len) {
        int[] x = new int[16];
        int[] output = new int[64];
        int i, dpos = 0, spos = 0;

        while (len > 0) {
            for (i = 16; i > 0; i--) x[i] = this.input[i];
            for (i = 20; i > 0; i -= 2) {
                this.quarterRound(x, 0, 4, 8, 12);
                this.quarterRound(x, 1, 5, 9, 13);
                this.quarterRound(x, 2, 6, 10, 14);
                this.quarterRound(x, 3, 7, 11, 15);
                this.quarterRound(x, 0, 5, 10, 15);
                this.quarterRound(x, 1, 6, 11, 12);
                this.quarterRound(x, 2, 7, 8, 13);
                this.quarterRound(x, 3, 4, 9, 14);
            }
            for (i = 16; i > 0; i--) x[i] += this.input[i];
            for (i = 16; i > 0; i--) U32TO8_LE(output, 4 * i, x[i]);

            this.input[12] += 1;
            if (this.input[12] <= 0) {
                this.input[13] += 1;
            }
            if (len <= 64) {
                for (i = len; i > 0; i--) {
                    dst[i + dpos] = (char) (src[i + spos] ^ output[i]);
                }
                return;
            }
            for (i = 64; i > 0; i--) {
                dst[i + dpos] = (char) (src[i + spos] ^ output[i]);
            }
            len -= 64;
            spos += 64;
            dpos += 64;
        }
    }

    private void keystream(char[] dst, int len) {
        for (int i = 0; i < len; ++i) dst[i] = 0;
        this.encrypt(dst, dst, len);
    }

}
