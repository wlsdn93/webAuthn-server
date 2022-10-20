package com.practice.fido.webAuthn.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import java.io.IOException;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class WebAuthnUtil {
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static byte[] hash(String clientDataJson) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(decoder.decode(clientDataJson));
        return md.digest();
    }

    public static String stringifyCBOR(byte[] cbor) throws IOException {
        CBORFactory cborFactory = new CBORFactory();
        CBORParser parser = cborFactory.createParser(cbor);

        JsonFactory jsonFactory = new JsonFactory();
        StringWriter stringWriter = new StringWriter();
        JsonGenerator jsonGenerator = jsonFactory.createGenerator(stringWriter);
        while(parser.nextToken() != null) {
            jsonGenerator.copyCurrentEvent(parser);
        }
        jsonGenerator.flush();
        return stringWriter.toString();
    }

}
