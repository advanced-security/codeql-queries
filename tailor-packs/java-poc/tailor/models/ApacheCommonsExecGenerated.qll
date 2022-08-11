import java
private import semmle.code.java.dataflow.ExternalFlow

// No SinkModel found

// No SourceModel found

private class ApacheCommonsExecSummaryModelCustom extends SummaryModelCsv {
  override predicate row(string row) {
    row = [
      "org.apache.commons.exec.environment;DefaultProcessingEnvironment;true;getProcEnvironment;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec.environment;EnvironmentUtils;true;addVariableToEnvironment;(Map,String);;Argument[1];Argument[0].Element;taint;generated",
      "org.apache.commons.exec.environment;EnvironmentUtils;true;toStrings;(Map);;Argument[0].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec.launcher;CommandLauncherProxy;true;CommandLauncherProxy;(CommandLauncher);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec.launcher;OS2CommandLauncher;true;OS2CommandLauncher;(CommandLauncher);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec.launcher;WinNTCommandLauncher;true;WinNTCommandLauncher;(CommandLauncher);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec.util;MapUtils;true;copy;(Map);;Argument[0].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec.util;MapUtils;true;merge;(Map,Map);;Argument[0].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec.util;MapUtils;true;merge;(Map,Map);;Argument[1].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec.util;MapUtils;true;prefix;(Map,String);;Argument[0].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec.util;MapUtils;true;prefix;(Map,String);;Argument[1];ReturnValue;taint;generated",
      "org.apache.commons.exec.util;StringUtils;true;quoteArgument;(String);;Argument[0];ReturnValue;taint;generated",
      "org.apache.commons.exec.util;StringUtils;true;split;(String,String);;Argument[0];ReturnValue;taint;generated",
      "org.apache.commons.exec.util;StringUtils;true;stringSubstitution;(String,Map,boolean);;Argument[0];ReturnValue;taint;generated",
      "org.apache.commons.exec.util;StringUtils;true;toString;(String[],String);;Argument[0].ArrayElement;ReturnValue;taint;generated",
      "org.apache.commons.exec.util;StringUtils;true;toString;(String[],String);;Argument[1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;CommandLine;(CommandLine);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;CommandLine;true;addArgument;(String);;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;addArgument;(String,boolean);;Argument[-1];ReturnValue;value;generated",
      "org.apache.commons.exec;CommandLine;true;addArguments;(String);;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;addArguments;(String,boolean);;Argument[-1];ReturnValue;value;generated",
      "org.apache.commons.exec;CommandLine;true;addArguments;(String[]);;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;addArguments;(String[],boolean);;Argument[-1];ReturnValue;value;generated",
      "org.apache.commons.exec;CommandLine;true;getArguments;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;getSubstitutionMap;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;parse;(String,Map);;Argument[1].Element;ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;setSubstitutionMap;(Map);;Argument[0].Element;Argument[-1];taint;generated",
      "org.apache.commons.exec;CommandLine;true;toString;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;CommandLine;true;toStrings;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;DefaultExecuteResultHandler;true;getException;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;ExecuteException;true;ExecuteException;(String,int,Throwable);;Argument[2];Argument[-1];taint;generated",
      "org.apache.commons.exec;ExecuteResultHandler;true;onProcessFailed;(ExecuteException);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;ExecuteStreamHandler;true;setProcessInputStream;(OutputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;ExecuteWatchdog;true;failedToStart;(Exception);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;ExecuteWatchdog;true;start;(Process);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;Executor;true;getProcessDestroyer;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;Executor;true;getStreamHandler;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;Executor;true;getWatchdog;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;Executor;true;getWorkingDirectory;();;Argument[-1];ReturnValue;taint;generated",
      "org.apache.commons.exec;Executor;true;setProcessDestroyer;(ProcessDestroyer);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;Executor;true;setStreamHandler;(ExecuteStreamHandler);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;Executor;true;setWatchdog;(ExecuteWatchdog);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;Executor;true;setWorkingDirectory;(File);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;InputStreamPumper;true;InputStreamPumper;(InputStream,OutputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;InputStreamPumper;true;InputStreamPumper;(InputStream,OutputStream);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;ProcessDestroyer;true;add;(Process);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream,OutputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream,OutputStream);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream,OutputStream,InputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream,OutputStream,InputStream);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;PumpStreamHandler;true;PumpStreamHandler;(OutputStream,OutputStream,InputStream);;Argument[2];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream,boolean);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream,boolean);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream,boolean,int);;Argument[0];Argument[-1];taint;generated",
      "org.apache.commons.exec;StreamPumper;true;StreamPumper;(InputStream,OutputStream,boolean,int);;Argument[1];Argument[-1];taint;generated",
      "org.apache.commons.exec;Watchdog;true;addTimeoutObserver;(TimeoutObserver);;Argument[0];Argument[-1];taint;generated"
    ]
  }
}

