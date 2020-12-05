import java.util.HashMap;

public class Ichecker {
    public static void main(String[] args) throws Exception{
        //Identifying arguments
        HashMap<String,String> arguments = identifyArgs(args);

        //Executing the given command
        switch (args[0]) {
            case "createCert": new CreateCertification(arguments); break;
            case "createReg" : new CreateRegistry     (arguments); break;
            case "check"     : new CheckIntegrity     (arguments); break;

            default: System.err.println("Command couldn't be recognized!"); break;
        }
    }

    private static HashMap<String,String> identifyArgs(String[] args) {
        HashMap<String,String> arguments = new HashMap<>();

        for (int i = 1; i < args.length; i++)
            switch (args[i]) {
                case "-l": arguments.put("log", args[i + 1]);      break;
                case "-p": arguments.put("path", args[i + 1]);     break;
                case "-h": arguments.put("hash", args[i + 1]);     break;
                case "-c": arguments.put("public", args[i + 1]);   break;
                case "-k": arguments.put("private", args[i + 1]);  break;
                case "-r": arguments.put("registry", args[i + 1]); break;
            }   return arguments;
    }
}
