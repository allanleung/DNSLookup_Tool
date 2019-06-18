package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();
    private static short questionID;
    private static int offset;
    private static ByteBuffer buffer;
    private static List<ResourceRecord> nameservers;


    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    System.out.print("DNSLOOKUP> ");
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }



    private static void createRequestHeader() {

        questionID = (short) random.nextInt(Short.MAX_VALUE);
        buffer.putShort(0, questionID);
        // QR, OPCODE, AA, TC, RD, RA, Z, RCODE = 0
        long zero = (long) 0;
        buffer.putLong(2, zero);
        //QDCOUNT
        short QDCOUNT = (short) 1;
        buffer.putShort(4, QDCOUNT);
        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        buffer.putLong(6, zero);
        buffer.putShort(10, (short) 0);
        offset = 12;

    }

    private static void fillOutQNAME(String hostName){
        String[] hostNameSubstrings = hostName.split("\\.");

        for (String hostNameString: hostNameSubstrings){

            int length = hostNameString.length();
            try {
                byte[] hostNameCharacters = hostNameString.getBytes("UTF-8");
                buffer.put(offset, (byte) length);
                offset++;

                for (int i = 0; i < length; i++){
                    buffer.put(offset + i, hostNameCharacters[i]);
                }

                offset = offset + length;
            } catch (UnsupportedEncodingException e) {
                System.err.println("Host Name conversion failed: " + e.getMessage());
            }

        }
        buffer.put(offset, (byte) 0);
        offset++;

    }


    private static void createRequestQuestion(DNSNode node) {

        fillOutQNAME(node.getHostName());
        short QTYPE = (short) node.getType().getCode();
        buffer.putShort(offset, QTYPE);
        short QCLASS = (short) 1;   // CLASS = INTERNET
        buffer.putShort(offset + 2, QCLASS);
        offset = offset + 4;

    }


    private static byte[] createRequest(DNSNode node) {

        buffer = ByteBuffer.allocate(512);
        createRequestHeader();
        createRequestQuestion(node);

        byte[] requestBuf = Arrays.copyOfRange(buffer.array(), 0, offset);
        return requestBuf;

    }



    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
        Set<ResourceRecord> results = cache.getCachedResults(node);
        Set<ResourceRecord> resultsCname = cache.getCachedResults(cnameNode);

        if (results.isEmpty() && resultsCname.isEmpty()) {
            retrieveResultsFromServer(node, rootServer);
            results = cache.getCachedResults(node);
            resultsCname = cache.getCachedResults(cnameNode);
        }

        if (!resultsCname.isEmpty()) {
            results = new HashSet<>(results);
            for (ResourceRecord cnameRecord : resultsCname) {
                results.addAll(getResults(new DNSNode(cnameRecord.getTextResult(), node.getType()), indirectionLevel + 1));
            }
        }

        return results;


    }



    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // TODO To be completed by the student

        socket.connect(server, DEFAULT_DNS_PORT);

        byte[] requestBuf = createRequest(node);
        byte[] resultBuf = new byte[1024];

        DatagramPacket packet = new DatagramPacket(requestBuf, requestBuf.length, server, DEFAULT_DNS_PORT);
        DatagramPacket receivePacket = new DatagramPacket(resultBuf, resultBuf.length);

        boolean resend = true;

        while (resend) {
            try {

                // send resquest to server
                socket.send(packet);

                // receive result from server
                socket.receive(receivePacket);

                // decode result
                DNSResponse helper = new DNSResponse(node, resultBuf);
                helper.decodeResponse(questionID);

                if (verboseTracing) {
                    printDNSResponse(node, helper, server);
                }

                // result is authoritative
                if (helper.isAuthoritative()) {
                    return;
                }

                // result is not authoritative
                nameservers = helper.getNameServerRecords();
                retrieveResultsFromNameServer(node);

                return;


            } catch (SocketTimeoutException se) {
                resend = false;
                retrieveResultsFromNameServer(node);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        System.err.println("Name cannot be looked up.");
        return;

    }

    private static void retrieveResultsFromNameServer(DNSNode node) {
        if (nameservers.size() != 0) {

            String NS = nameservers.get(random.nextInt(nameservers.size())).getTextResult();
            DNSNode NSNode = new DNSNode(NS, RecordType.A);
            Set<ResourceRecord> results = cache.getCachedResults(NSNode);
            results.forEach(result -> {
                retrieveResultsFromServer(node, result.getInetResult());
            });

        }
    }

    public static int getRequestEndPosition(){
        return offset;
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    private static void printDNSResponse(DNSNode node, DNSResponse response, InetAddress server) {
        boolean isAuthoritative = response.isAuthoritative();

        System.out.println("Query ID    " + questionID + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
        System.out.println("Respond ID: " + questionID + " Authoritative = " + isAuthoritative);
        ArrayList<ResourceRecord> answers = response.getAnswerRecords();
        System.out.println("  Answers (" + answers.size() + ")");
        answers.forEach(answer -> verbosePrintResourceRecord(answer, answer.getType().getCode()));

        ArrayList<ResourceRecord> nameServers = response.getNameServerRecords();
        System.out.println("  Nameservers (" + nameServers.size() + ")");
        nameServers.forEach(nameServer -> verbosePrintResourceRecord(nameServer, nameServer.getType().getCode()));

        ArrayList<ResourceRecord> addtionals = response.getAdditionalInfoRecords();
        System.out.println("  Additional Information (" + addtionals.size() + ")");
        addtionals.forEach(additional -> verbosePrintResourceRecord(additional, additional.getType().getCode()));

    }

}