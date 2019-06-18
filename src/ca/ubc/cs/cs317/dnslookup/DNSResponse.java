package ca.ubc.cs.cs317.dnslookup;

import java.io.UnsupportedEncodingException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ShortBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by carlyhuang on 2018-11-02.
 */
public class DNSResponse {

    private int ANCOUNT;
    private int NSCOUNT;
    private int ARCOUNT;
    private DNSNode node;
    private byte[] response;
    ByteBuffer buffer;
    private int offset;
    private int pointerOffset;
    private boolean isBeginning;
    private boolean isAuthoritative;

    private static DNSCache cache = DNSCache.getInstance();

    private ArrayList<ResourceRecord> answerRecords = new ArrayList<ResourceRecord>();
    private ArrayList<ResourceRecord> nameServerRecords = new ArrayList<ResourceRecord>();
    private ArrayList<ResourceRecord> additionalInfoRecords = new ArrayList<ResourceRecord>();


    public DNSResponse(DNSNode node, byte[] response) {

        buffer = ByteBuffer.allocate(response.length).put(response);

        this.node = node;
        this.response = response;

    }

    public void decodeResponse(short queryID) {

        decodeHeader(queryID);
        offset = DNSLookupService.getRequestEndPosition();

        for (int i = 0; i < ANCOUNT; i++) {
            ResourceRecord record = getRecord();
            RecordType type = record.getType();
            if (type == RecordType.A || type == RecordType.AAAA || type == RecordType.CNAME) {
                answerRecords.add(record);
            }

        }

        for (int i = 0; i < NSCOUNT; i++) {
            ResourceRecord record = getRecord();
            RecordType type = record.getType();
            if (type == RecordType.NS) {
                nameServerRecords.add(record);
            }

        }

        for (int i = 0; i < ARCOUNT; i++) {
            ResourceRecord record = getRecord();
            RecordType type = record.getType();
            if (type == RecordType.A || type == RecordType.AAAA) {
                additionalInfoRecords.add(record);
            }

        }
    }

    public void decodeHeader(short queryID){
        // The Header is 12 bytes long, we are doing byte by byte and categorizing them according

        short id = buffer.getShort(0);
        if (id != queryID){
            System.err.println("Query ID doesn't match.");
        }
        ANCOUNT = (int) buffer.getShort(6);
        NSCOUNT = (int) buffer.getShort(8);
        ARCOUNT = (int) buffer.getShort(10);
        checkAA();
    }

    private void checkAA() {
        // Helper to check if a Authoritative Server exist from the two bytes
        // Byte shift 2 to right
        int section = Byte.toUnsignedInt(buffer.get(2));
        section >>>= 2;
        section &= 0x1;
        if (section == 1){
            isAuthoritative = true;
        } else {
            isAuthoritative = false;
        }

    }


    private ResourceRecord getRecord() {
        //
        int labelTag = Byte.toUnsignedInt(buffer.get(offset)) >>> 6;
        // this is to grab all the domain name in the packet
        String hostName = node.getHostName();
        if (labelTag == 3 ) {
            // NAME is a pointer
            getPointer(offset);
            isBeginning = true;
            hostName = getDomainName(pointerOffset);
            offset += 2;
        } else {
            isBeginning = true;
            getDomainName(offset);
            findNewOffset();

        }
        int type = Short.toUnsignedInt(buffer.getShort(offset));
        RecordType TYPE = RecordType.getByCode(type);
        // Grab the Time to Live from the packet
        int ttl = (Byte.toUnsignedInt(buffer.get(offset + 4)) << 24)
                + (Byte.toUnsignedInt(buffer.get(offset + 5)) << 16)
                + (Byte.toUnsignedInt(buffer.get(offset + 6)) << 8)
                + Byte.toUnsignedInt(buffer.get(offset + 7));
//        System.out.println("ttl is: " + ttl);

        long TTL = ttl;
        int RDLENGTH = Short.toUnsignedInt(buffer.getShort(offset + 8));
        offset = offset + 10;


        ResourceRecord newRecord;


        if (TYPE == RecordType.A) {

            byte[] RDATA = Arrays.copyOfRange(response, offset, offset + RDLENGTH);
            InetAddress IP = resolveIPV4Result(RDATA);
            newRecord = new ResourceRecord(hostName, TYPE, TTL, IP);

            // Check for NS and CNAME

        } else if (TYPE == RecordType.NS || TYPE == RecordType.CNAME) {
            isBeginning = true;
            String result = getDomainName(offset);
            newRecord = new ResourceRecord(hostName, TYPE, TTL, result);

            // check for IPv6

        } else if (TYPE == RecordType.AAAA) {
            byte[] RDATA = Arrays.copyOfRange(response, offset, offset + RDLENGTH);
            InetAddress IP = resolveIPV6Result(hostName, RDATA);
            newRecord = new ResourceRecord(hostName, TYPE, TTL, IP);

        } else {
            newRecord = new ResourceRecord(hostName, TYPE, TTL, "");
        }
        // This is when we know we are near the end of the packet and add to cache
        // We know its the end once we hit RDLENGTH
        offset = offset + RDLENGTH;
        cache.addResult(newRecord);
        return newRecord;
    }

    private static InetAddress resolveIPV4Result(byte[] data) {

        InetAddress address = null;
        try {
            address = InetAddress.getByAddress(data);

        } catch (UnknownHostException e) {
            System.err.println("Invalid IP Address: " + e.getMessage());
        }
        return address;

    }


    private static InetAddress resolveIPV6Result(String host, byte[] data) {

        InetAddress address = null;
        try {
            address = Inet6Address.getByAddress(host, data);

        } catch (UnknownHostException e) {
            System.err.println("Invalid IP Address: " + e.getMessage());
        }
        return address;

    }


    public ArrayList<ResourceRecord> getAnswerRecords() {
        return answerRecords;
    }

    public ArrayList<ResourceRecord> getNameServerRecords() {
        return nameServerRecords;
    }

    public ArrayList<ResourceRecord> getAdditionalInfoRecords() {
        return additionalInfoRecords;
    }

    public boolean isAuthoritative() {
        return isAuthoritative;
    }


    private String getDomainName(int ptr) {
        // Grab domain name
        String domainName = "";

        while (response[ptr] != 0) {
            if (response[ptr] < 0) {
                getPointer(ptr);
                return domainName + getDomainName(pointerOffset);
            }
            if (!isBeginning) domainName = domainName + ".";
            int count = Byte.toUnsignedInt(response[ptr]);
            ptr++;
            byte[] name = Arrays.copyOfRange(response, ptr, ptr + count);
            domainName = domainName + byteToAcsii(name);
            ptr += count;
            isBeginning = false;
        }

        return domainName;

    }


    private static String byteToAcsii(byte[] buffer) {

        String ascii = "";
        try {
            ascii = new String(buffer, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            System.err.println(e.getMessage());
        }
        return ascii;
    }

    private void getPointer(int index) {

        int ptr = Short.toUnsignedInt(buffer.getShort(index));
        pointerOffset = ptr ^ 0xc000;

    }


    private void findNewOffset() {
        while (response[offset] != 0 && response[offset] > 0){
            offset++;
        }
        if (response[offset] == 0){
            offset++;
        } else {
            offset+=2;
        }
    }


}

