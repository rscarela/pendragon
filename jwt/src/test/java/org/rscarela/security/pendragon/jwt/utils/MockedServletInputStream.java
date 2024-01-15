package org.rscarela.security.pendragon.jwt.utils;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class MockedServletInputStream extends ServletInputStream {

    private InputStream inputStream;

    public MockedServletInputStream(String content) {
        super();
        this.inputStream = new ByteArrayInputStream(content.getBytes());
    }

    @Override
    public boolean isFinished() {
        return true;
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener listener) {
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }
}
