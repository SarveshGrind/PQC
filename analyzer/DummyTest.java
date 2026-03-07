import java.security.Signature;
public class DummyTest {
    public void test() throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
    }
}
