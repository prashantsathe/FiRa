package com.android.javacard.SecureChannels;

public abstract class FiraSecureChannel {
    public static final byte FIRA_SC_PROTOCOL = 0;
    public static final byte FIRA_SCP11c_PROTOCOL = 1;

    public abstract short initiate(byte[] appletId, short start, short appletIdLen, byte[] oidBuf,
            short oidStart, short oidEnd, byte[] buf,
            short index, short len);
    public abstract void terminate();
    public abstract short handleProtocolObject(byte[] buf, short index, short len);
    public abstract short wrap(byte[] buf, short index, short len);
    public abstract short unwrap(byte[] buf, short index, short len);
    public abstract byte getProtocolType();
    public abstract short getEventData(byte eventId, byte[] buf, short index);
    public abstract short generateRds(byte[] output, short outputOffset, short outputLength,
            byte[] sessionKeyInfo, short start, short len,
            boolean useSessionKeyInfo, boolean useForDiversification);

    public static FiraSecureChannel create(byte type, FiraClientContext context) {
        if (type == FIRA_SC_PROTOCOL) {
            return new FiraSC(context);
        } else if(type == FIRA_SCP11c_PROTOCOL) {
            return new Scp(context);
        }
        return null;
    }
}

