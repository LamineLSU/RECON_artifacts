package soot.jimple.infoflow.cmd;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.lang.String;
import java.util.concurrent.TimeoutException;
import java.nio.file.AccessDeniedException;
import java.util.zip.ZipException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import heros.InterproceduralCFG;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.Stmt;
import soot.Body;
import soot.G;
import soot.Value;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.UnitBox;
import soot.jimple.AssignStmt;
import soot.jimple.GotoStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.infoflow.InfoflowConfiguration.AliasingAlgorithm;
import soot.jimple.infoflow.InfoflowConfiguration.CallbackSourceMode;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.InfoflowConfiguration.CodeEliminationMode;
import soot.jimple.infoflow.InfoflowConfiguration.DataFlowDirection;
import soot.jimple.infoflow.InfoflowConfiguration.DataFlowSolver;
import soot.jimple.infoflow.InfoflowConfiguration.ImplicitFlowMode;
import soot.jimple.infoflow.InfoflowConfiguration.LayoutMatchingMode;
import soot.jimple.infoflow.InfoflowConfiguration.PathBuildingAlgorithm;
import soot.jimple.infoflow.InfoflowConfiguration.PathReconstructionMode;
import soot.jimple.infoflow.InfoflowConfiguration.StaticFieldTrackingMode;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration.CallbackAnalyzer;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.config.XMLConfigurationParser;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
import soot.jimple.infoflow.cmd.AllocationGraphAnalyzer.MethodAnalysisResult;
import soot.jimple.infoflow.methodSummary.data.provider.LazySummaryProvider;
import soot.jimple.infoflow.methodSummary.taintWrappers.ReportMissingSummaryWrapper;
import soot.jimple.infoflow.methodSummary.taintWrappers.SummaryTaintWrapper;
import soot.jimple.infoflow.methodSummary.taintWrappers.TaintWrapperFactory;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.infoflow.taintWrappers.TaintWrapperSet;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.tools.CFGViewer;
import soot.util.HashMultiMap;
import soot.util.MultiMap;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.entryPointCreators.*;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.SwitchStmt;

/**
 * Main class for running FlowDroid from the command-line
 * 
 * @author Steven Arzt
 *
 */
public class MainClass {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	protected final Options options = new Options();
	protected SetupApplication analyzer = null;
	protected ReportMissingSummaryWrapper reportMissingSummaryWrapper;
	public String appPackageName;
	private static final int BATCH_SIZE = 50;
	private static final long MIN_MEMORY_THRESHOLD = 100 * 1024 * 1024; // 100MB
	protected Set<String> filesToSkip = new HashSet<>();
	private CallGraph callGraph;
	private String outputDir;
	private static final String OUTPUT_DIR_BASE = "analysisOutput/";
	private String appOutputDir;
	private Map<String, AllocationNode> allNodes = new HashMap<>();
	private Map<String, Set<String>> allEdges = new HashMap<>();
	private Map<String, SootMethod> lambdaToOnClick = new HashMap<>();
	private Set<String> processedOnClick = new HashSet<>();

	// Files
	private static final String OPTION_CONFIG_FILE = "c";
	private static final String OPTION_APK_FILE = "a";
	private static final String OPTION_PLATFORMS_DIR = "p";
	private static final String OPTION_SOURCES_SINKS_FILE = "s";
	private static final String OPTION_OUTPUT_FILE = "o";
	private static final String OPTION_ADDITIONAL_CLASSPATH = "ac";
	private static final String OPTION_SKIP_APK_FILE = "si";
	private static final String OPTION_WRITE_JIMPLE_FILES = "wj";

	// Timeouts
	private static final String OPTION_TIMEOUT = "dt";
	private static final String OPTION_CALLBACK_TIMEOUT = "ct";
	private static final String OPTION_RESULT_TIMEOUT = "rt";

	// Optional features
	private static final String OPTION_NO_STATIC_FLOWS = "ns";
	private static final String OPTION_NO_CALLBACK_ANALYSIS = "nc";
	private static final String OPTION_NO_EXCEPTIONAL_FLOWS = "ne";
	private static final String OPTION_NO_TYPE_CHECKING = "nt";
	private static final String OPTION_REFLECTION = "r";
	private static final String OPTION_MISSING_SUMMARIES_FILE = "ms";
	private static final String OPTION_OUTPUT_LINENUMBERS = "ol";
	private static final String OPTION_ORIGINAL_NAMES = "on";

	// Taint wrapper
	private static final String OPTION_TAINT_WRAPPER = "tw";
	private static final String OPTION_TAINT_WRAPPER_FILE = "t";

	// Individual settings
	private static final String OPTION_ACCESS_PATH_LENGTH = "al";
	private static final String OPTION_NO_THIS_CHAIN_REDUCTION = "nr";
	private static final String OPTION_FLOW_INSENSITIVE_ALIASING = "af";
	private static final String OPTION_COMPUTE_PATHS = "cp";
	private static final String OPTION_ONE_SOURCE = "os";
	private static final String OPTION_ONE_COMPONENT = "ot";
	private static final String OPTION_SEQUENTIAL_PATHS = "sp";
	private static final String OPTION_LOG_SOURCES_SINKS = "ls";
	private static final String OPTION_MERGE_DEX_FILES = "d";
	private static final String OPTION_SINGLE_JOIN_POINT = "sa";
	private static final String OPTION_MAX_CALLBACKS_COMPONENT = "mc";
	private static final String OPTION_MAX_CALLBACKS_DEPTH = "md";
	private static final String OPTION_PATH_SPECIFIC_RESULTS = "ps";
	private static final String OPTION_MAX_THREAD_NUMBER = "mt";
	private static final String OPTION_LENIENT_PARSING_MODE = "lp";

	// Inter-component communication
	private static final String OPTION_ICC_MODEL = "im";
	private static final String OPTION_ICC_NO_PURIFY = "np";

	// Modes and algorithms
	private static final String OPTION_CALLGRAPH_ALGO = "cg";
	private static final String OPTION_LAYOUT_MODE = "l";
	private static final String OPTION_PATH_RECONSTRUCTION_ALGO = "pa";
	private static final String OPTION_CALLBACK_ANALYZER = "ca";
	private static final String OPTION_DATA_FLOW_SOLVER = "ds";
	private static final String OPTION_ALIAS_ALGO = "aa";
	private static final String OPTION_CODE_ELIMINATION_MODE = "ce";
	private static final String OPTION_CALLBACK_SOURCE_MODE = "cs";
	private static final String OPTION_PATH_RECONSTRUCTION_MODE = "pr";
	private static final String OPTION_IMPLICIT_FLOW_MODE = "i";
	private static final String OPTION_STATIC_FLOW_TRACKING_MODE = "sf";
	private static final String OPTION_DATA_FLOW_DIRECTION = "dir";
	private static final String OPTION_GC_SLEEP_TIME = "st";

	// Evaluation-specific options
	private static final String OPTION_ANALYZE_FRAMEWORKS = "ff";

	// Callgraph analysis
	private static final String OPTION_CALLGRAPH_FILE = "cf";
	private static final String OPTION_CALLGRAPH_ONLY = "x";

	protected MainClass() {
		initializeCommandLineOptions();
	}

	/**
	 * Initializes the set of available command-line options
	 */
	private void initializeCommandLineOptions() {
		options.addOption("?", "help", false, "Print this help message");

		// Files
		options.addOption(OPTION_CONFIG_FILE, "configfile", true, "Use the given configuration file");
		options.addOption(OPTION_APK_FILE, "apkfile", true, "APK file to analyze");
		options.addOption(OPTION_PLATFORMS_DIR, "platformsdir", true,
				"Path to the platforms directory from the Android SDK");
		options.addOption(OPTION_SOURCES_SINKS_FILE, "sourcessinksfile", true, "Definition file for sources and sinks");
		options.addOption(OPTION_OUTPUT_FILE, "outputfile", true, "Output XML file for the discovered data flows");
		options.addOption(OPTION_ADDITIONAL_CLASSPATH, "additionalclasspath", true,
				"Additional JAR file that shal be put on the classpath");
		options.addOption(OPTION_SKIP_APK_FILE, "skipapkfile", true,
				"APK file to skip when processing a directory of input files");
		options.addOption(OPTION_WRITE_JIMPLE_FILES, "writejimplefiles", true, "Write out the Jimple files");

		// Timeouts
		options.addOption(OPTION_TIMEOUT, "timeout", true, "Timeout for the main data flow analysis");
		options.addOption(OPTION_CALLBACK_TIMEOUT, "callbacktimeout", true,
				"Timeout for the callback collection phase");
		options.addOption(OPTION_RESULT_TIMEOUT, "resulttimeout", true, "Timeout for the result collection phase");

		// Optional features
		options.addOption(OPTION_NO_STATIC_FLOWS, "nostatic", false, "Do not track static data flows");
		options.addOption(OPTION_NO_CALLBACK_ANALYSIS, "nocallbacks", false, "Do not analyze Android callbacks");
		options.addOption(OPTION_NO_EXCEPTIONAL_FLOWS, "noexceptions", false,
				"Do not track taints across exceptional control flow edges");
		options.addOption(OPTION_NO_TYPE_CHECKING, "notypechecking", false,
				"Disable type checking during taint propagation");
		options.addOption(OPTION_REFLECTION, "enablereflection", false, "Enable support for reflective method calls");
		options.addOption(OPTION_MISSING_SUMMARIES_FILE, "missingsummariesoutputfile", true,
				"Outputs a file with information about which summaries are missing");
		options.addOption(OPTION_OUTPUT_LINENUMBERS, "outputlinenumbers", false,
				"Enable the output of bytecode line numbers associated with sources and sinks in XML results");
		options.addOption(OPTION_ORIGINAL_NAMES, "originalnames", false,
				"Enable the usage of original variablenames if available");

		// Taint wrapper
		options.addOption(OPTION_TAINT_WRAPPER, "taintwrapper", true,
				"Use the specified taint wrapper algorithm (NONE, EASY, STUBDROID, MULTI)");
		options.addOption(OPTION_TAINT_WRAPPER_FILE, "taintwrapperfile", true, "Definition file for the taint wrapper");

		// Individual settings
		options.addOption(OPTION_ACCESS_PATH_LENGTH, "aplength", true, "Maximum access path length");
		options.addOption(OPTION_NO_THIS_CHAIN_REDUCTION, "nothischainreduction", false,
				"Disable reduction of inner class chains");
		options.addOption(OPTION_FLOW_INSENSITIVE_ALIASING, "aliasflowins", false,
				"Use a flow-insensitive alias analysis");
		options.addOption(OPTION_COMPUTE_PATHS, "paths", false,
				"Compute the taint propagation paths and not just source-to-sink connections. This is a shorthand notation for -pr fast.");
		options.addOption(OPTION_LOG_SOURCES_SINKS, "logsourcesandsinks", false,
				"Write the discovered sources and sinks to the log output");
		options.addOption(OPTION_MAX_THREAD_NUMBER, "maxthreadnum", true,
				"Limit the maximum number of threads to the given value");
		options.addOption(OPTION_ONE_COMPONENT, "onecomponentatatime", false,
				"Analyze one Android component at a time");
		options.addOption(OPTION_ONE_SOURCE, "onesourceatatime", false, "Analyze one source at a time");
		options.addOption(OPTION_SEQUENTIAL_PATHS, "sequentialpathprocessing", false,
				"Process the result paths sequentially instead of in parallel");
		options.addOption(OPTION_SINGLE_JOIN_POINT, "singlejoinpointabstraction", false,
				"Only use a single abstraction at join points, i.e., do not support multiple sources for one value");
		options.addOption(OPTION_MAX_CALLBACKS_COMPONENT, "maxcallbackspercomponent", true,
				"Eliminate Android components that have more than the given number of callbacks");
		options.addOption(OPTION_MAX_CALLBACKS_DEPTH, "maxcallbacksdepth", true,
				"Only analyze callback chains up to the given depth");
		options.addOption(OPTION_MERGE_DEX_FILES, "mergedexfiles", false,
				"Merge all dex files in the given APK file into one analysis target");
		options.addOption(OPTION_PATH_SPECIFIC_RESULTS, "pathspecificresults", false,
				"Report different results for same source/sink pairs if they differ in their propagation paths");

		// Inter-component communication
		options.addOption(OPTION_ICC_MODEL, "iccmodel", true,
				"File containing the inter-component data flow model (ICC model)");
		options.addOption(OPTION_ICC_NO_PURIFY, "noiccresultspurify", false,
				"Do not purify the ICC results, i.e., do not remove simple flows that also have a corresponding ICC flow");

		// Modes and algorithms
		options.addOption(OPTION_CALLGRAPH_ALGO, "cgalgo", true,
				"Callgraph algorithm to use (AUTO, CHA, VTA, RTA, SPARK, GEOM)");
		options.addOption(OPTION_LAYOUT_MODE, "layoutmode", true,
				"Mode for considerung layout controls as sources (NONE, PWD, ALL)");
		options.addOption(OPTION_PATH_RECONSTRUCTION_ALGO, "pathalgo", true,
				"Use the specified algorithm for computing result paths (CONTEXTSENSITIVE, CONTEXTINSENSITIVE, SOURCESONLY)");
		options.addOption(OPTION_CALLBACK_ANALYZER, "callbackanalyzer", true,
				"Use the specified callback analyzer (DEFAULT, FAST)");
		options.addOption(OPTION_DATA_FLOW_SOLVER, "dataflowsolver", true,
				"Use the specified data flow solver (CONTEXTFLOWSENSITIVE, FLOWINSENSITIVE)");
		options.addOption(OPTION_ALIAS_ALGO, "aliasalgo", true,
				"Use the specified aliasing algorithm (NONE, FLOWSENSITIVE, PTSBASED, LAZY)");
		options.addOption(OPTION_CODE_ELIMINATION_MODE, "codeelimination", true,
				"Use the specified code elimination algorithm (NONE, PROPAGATECONSTS, REMOVECODE)");
		options.addOption(OPTION_CALLBACK_SOURCE_MODE, "callbacksourcemode", true,
				"Use the specified mode for defining which callbacks introduce which sources (NONE, ALL, SOURCELIST)");
		options.addOption(OPTION_PATH_RECONSTRUCTION_MODE, "pathreconstructionmode", true,
				"Use the specified mode for reconstructing taint propagation paths (NONE, FAST, PRECISE).");
		options.addOption(OPTION_IMPLICIT_FLOW_MODE, "implicit", true,
				"Use the specified mode when processing implicit data flows (NONE, ARRAYONLY, ALL)");
		options.addOption(OPTION_STATIC_FLOW_TRACKING_MODE, "staticmode", true,
				"Use the specified mode when tracking static data flows (CONTEXTFLOWSENSITIVE, CONTEXTFLOWINSENSITIVE, NONE)");
		options.addOption(OPTION_DATA_FLOW_DIRECTION, "direction", true,
				"Specifies the direction of the infoflow analysis (FORWARDS, BACKWARDS)");
		options.addOption(OPTION_GC_SLEEP_TIME, "gcsleeptime", true,
				"Specifies the sleep time for path edge collectors in seconds");

		// Evaluation-specific options
		options.addOption(OPTION_ANALYZE_FRAMEWORKS, "analyzeframeworks", false,
				"Analyze the full frameworks together with the app without any optimizations");

		// Callgraph-specific options
		options.addOption(OPTION_CALLGRAPH_FILE, "callgraphdir", true,
				"The file in which to store and from which to read serialized callgraphs");
		options.addOption(OPTION_CALLGRAPH_ONLY, "callgraphonly", false, "Only compute the callgraph and terminate");
		options.addOption(OPTION_LENIENT_PARSING_MODE, "lenientparsing", false,
				"Enables non-strict parsing, i.e. tries to continue rather than fail in case of a parsing error");
		options.addOption("cg", "callgraph", true,
				"Callgraph engine: cha | spark | none (default: cha)");
		options.addOption(null, "wpa", false,
				"Enable whole-program analysis (recommended)");
	}

	public static void main(String[] args) throws Exception {
		MainClass main = new MainClass();
		main.run(args);
	}

	protected void run(String[] args) throws Exception {
		// We need proper parameters
		final HelpFormatter formatter = new HelpFormatter();
		if (args.length == 0) {
			formatter.printHelp("soot-infoflow-cmd [OPTIONS]", options);
			return;
		}

		// Parse the command-line parameters
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);

			// Do we need to display the user manual?
			if (cmd.hasOption("?") || cmd.hasOption("help")) {
				formatter.printHelp("soot-infoflow-cmd [OPTIONS]", options);
				return;
			}

			// Do we have a configuration file?
			String configFile = cmd.getOptionValue(OPTION_CONFIG_FILE);
			final InfoflowAndroidConfiguration config = configFile == null || configFile.isEmpty()
					? new InfoflowAndroidConfiguration()
					: loadConfigurationFile(configFile);
			if (config == null)
				return;

			// Parse the other options
			parseCommandLineOptions(cmd, config);

			// We can analyze whole directories of apps. In that case, we must gather the
			// target APKs.
			File targetFile = config.getAnalysisFileConfig().getTargetAPKFile();
			if (!targetFile.exists()) {
				System.err.println(String.format("Target APK file %s does not exist", targetFile.getCanonicalPath()));
				return;
			}
			List<File> apksToAnalyze;
			if (targetFile.isDirectory()) {
				apksToAnalyze = Arrays.asList(targetFile.listFiles(new FilenameFilter() {

					@Override
					public boolean accept(File dir, String name) {
						return name.toLowerCase().endsWith(".apk");
					}

				}));
			} else
				apksToAnalyze = Collections.singletonList(targetFile);

			// In case we analyze multiple APKs, we want to have one file per app for the
			// results
			String outputFileStr = config.getAnalysisFileConfig().getOutputFile();
			File outputFile = null;
			if (outputFileStr != null && !outputFileStr.isEmpty()) {
				outputFile = new File(outputFileStr);
				if (outputFile.exists()) {
					if (apksToAnalyze.size() > 1 && outputFile.isFile()) {
						System.err.println("The output file must be a directory when analyzing multiple APKs");
						return;
					}
				} else if (apksToAnalyze.size() > 1)
					outputFile.mkdirs();
			}

			// Initialize the taint wrapper. We only do this once for all apps to cache
			// summaries that we have already loaded.
			ITaintPropagationWrapper taintWrapper = initializeTaintWrapper(cmd);

			int curAppIdx = 1;
			for (File apkFile : apksToAnalyze) {

				// === INITIALIZE RESULT COLLECTION FOR THIS APK ===
				String apkName = apkFile.getName();
				String apkPath = apkFile.getAbsolutePath();

				ApkAnalysisResult apkResult = new ApkAnalysisResult(apkName, apkPath, null); // packageName will be set
																								// later
				ResultPersistenceManager persistenceManager = new ResultPersistenceManager("./results");

				// Check if already analyzed (optional - for resume capability)
				if (persistenceManager.hasExistingAnalysis(apkName)) {
					System.out.println("APK already analyzed, skipping: " + apkName);
					continue;
				}

				if (filesToSkip.contains(apkFile.getName())) {
					logger.info(String.format("Skipping app %s (%d of %d)...", apkFile.getCanonicalPath(), curAppIdx++,
							apksToAnalyze.size()));
					continue;
				}
				logger.info(String.format("Analyzing app %s (%d of %d)...", apkFile.getCanonicalPath(), curAppIdx++,
						apksToAnalyze.size()));

				long fileSizeBytes = apkFile.length();
				long maxFileSizeBytes = 10 * 1024 * 1024; // 10MB

				if (fileSizeBytes > maxFileSizeBytes) {
					double sizeMB = fileSizeBytes / (1024 * 1024);
					System.err.println("SKIPPING: APK too large- " + apkFile.getCanonicalPath() + " ("
							+ String.format("%.1f", sizeMB) + " MB > 30MB limit");
					continue; // skip to the next apk
				}

				// Log APK size for monitoring
				double sizeMB = fileSizeBytes / (1024.0 * 1024.0);
				System.out.println("Processing APK: " + apkFile.getCanonicalPath() + " ("
						+ String.format("%.1f", sizeMB) + " MB)");

				// Configure the analyzer for the current APK file
				config.getAnalysisFileConfig().setTargetAPKFile(apkFile);
				if (outputFile != null) {
					if (apksToAnalyze.size() > 1 || (outputFile.exists() && outputFile.isDirectory())) {
						String outputFileName = apkFile.getName().replace(".apk", ".xml");
						File curOutputFile = new File(outputFile, outputFileName);
						config.getAnalysisFileConfig().setOutputFile(curOutputFile.getCanonicalPath());

						// If we have already analyzed this APK and we have the results, there is no
						// need to do it again
						if (curOutputFile.exists())
							continue;
					}
				}

				// Create the data flow analyzer
				analyzer = createFlowDroidInstance(config);

				CallGraph cg = null;
				try {
					analyzer.constructCallgraph();
					cg = Scene.v().getCallGraph();

					if (cg == null || cg.size() == 0) {
						System.err.println("WARNING: Empty call graph for " + apkFile.getName() + ", skipping...");
						continue; // Skip to next APK
					}

				} catch (RuntimeException e) {
					String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";

					if (errorMsg.contains("zipexception") || errorMsg.contains("encrypted entry")) {
						System.err.println("ERROR: APK is encrypted/packed - " + apkFile.getName());
					} else if (errorMsg.contains("manifest")) {
						System.err.println("ERROR: Manifest parsing failed - " + apkFile.getName());
					} else if (errorMsg.contains("invalid cen header")) {
						System.err.println("ERROR: APK file corrupted/encrypted - " + apkFile.getName());
					} else {
						System.err.println(
								"ERROR: FlowDroid setup failed - " + apkFile.getName() + ": " + e.getMessage());
					}

					apkResult.setAnalysisCompleted(false, e.getMessage());
					try {
						persistenceManager.saveApkAnalysisResult(apkResult);
					} catch (IOException saveError) {
						System.err.println("WARNING: could not save file analysis results: " + saveError.getMessage());
					}
					continue; // Skip to next APK

				} catch (OutOfMemoryError e) {
					System.err.println("ERROR: Out of memory analyzing " + apkFile.getName());
					System.gc(); // Force garbage collection

					apkResult.setAnalysisCompleted(false, "Out of memory error");
					try {
						persistenceManager.saveApkAnalysisResult(apkResult);
					} catch (IOException saveError) {
						System.err
								.println("WARNING: Could not save failed analysis results: " + saveError.getMessage());
					}
					continue; // Skip to next APK

				} catch (Exception e) {
					System.err.println("ERROR: Unexpected error during FlowDroid setup for " + apkFile.getName() + ": "
							+ e.getMessage());
					apkResult.setAnalysisCompleted(false, e.getMessage());
					try {
						persistenceManager.saveApkAnalysisResult(apkResult);
					} catch (IOException saveError) {
						System.err
								.println("WARNING: Could not save failed analysis results: " + saveError.getMessage());
					}

					continue; // Skip to next APK
				}

				System.out.println("Call graph constructed with " + cg.size() + " edges");

				// String apkPath = apkFile.getAbsolutePath();

				appPackageName = getPackageName(apkPath);
				// Set package name in result object
				apkResult.getApkMetadata().setPackageName(appPackageName);

				System.out.println(appPackageName);

				CallGraphExporter cgExporter = new CallGraphExporter();

				String timestamp = java.time.LocalDateTime.now()
						.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
				String sPackageName = appPackageName.replaceAll("[^a-zA-Z0-9._-]", "_");

				String jsonFileName = "./constraint_results/" + sPackageName + "_" + timestamp + "_call_graph.json";
				String dotFileName = "./constraint_results/" + sPackageName + "_" + timestamp + "_call_graph.dot";

				cgExporter.exportToJson(cg, jsonFileName);
				cgExporter.exportToDot(cg, dotFileName);
				cgExporter.printMethodStats(cg);

				try {
					// Get entry point classes from manifest
					Set<String> entryClasses = getEntryPoints(apkPath);

					System.out.println("=== Entry Point Classes from Manifest ===");
					for (String className : entryClasses) {
						System.out.println(className);
					}

					Set<SootClass> entrypoints = analyzer.getEntrypointClasses();
					System.out.println("=== Entry Point Classes from Analyzer ===");
					for (SootClass sClass : entrypoints) {
						System.out.println("======================================================");
						System.out.println(sClass.getName());
						System.out.println("======================================================");
						List<SootMethod> sootMethods = sClass.getMethods();
						for (SootMethod sm : sootMethods) {
							System.out.println(sm.getSignature());

						}
					}
					String sanitizePackageName = appPackageName.replaceAll("[^a-zA-Z0-9._-]",
							"_");
					String fileNameDot = sanitizePackageName + "SAG";

					// Initialize the analyzer
					AllocationGraphAnalyzer graphAnalyzer = new AllocationGraphAnalyzer();
					AnalysisConfig llm_config = new AnalysisConfig(LLMProvider.OPENAI,
							"",
							"gpt-4o", "./constraint_results");

					// Start from dummyMain
					graphAnalyzer.initializeAnalysis();

					// Run the analysis
					System.out.println("\n=== Starting Enhanced Analysis ===\n");
					graphAnalyzer.analyze();

					String cs = "com.rootminusone8004.bazarnote.MainActivity";
					SootClass sc = Scene.v().getSootClass(cs);

					for (SootMethod sMethod : sc.getMethods()) {
						String mSig = sMethod.getSignature();
						System.out.println("================= " + mSig + " ===================");
						printJimpleCode(sMethod);
						System.out.println("=================================================");

					}

					// === DANGEROUS API DETECTION PHASE ===
					System.out.println("\n=== DANGEROUS API DETECTION PHASE ===");
					DangerousApiDetector apiDetector = new DangerousApiDetector();
					DangerousApiScanResult scanResult = null;

					try {
						apiDetector.loadDangerousApiConfig("./dangerous_apis.json");
						scanResult = apiDetector.scanLoadedMethods();

						if (scanResult.getTotalFoundApis() == 0) {
							System.out.println("No dangerous APIs found in this APK - skipping constraint analysis");
							continue; // Skip to next APK
						}

						System.out.println(apiDetector.generateScanSummary(scanResult));

						for (Map.Entry<String, List<SootMethod>> entry : scanResult.getFoundApisByCategory()
								.entrySet()) {
							String category = entry.getKey();
							List<SootMethod> foundMethods = entry.getValue();

							// Get category info from detector
							DangerousApiCategory categoryInfo = apiDetector.getApiCategories().get(category);
							String severityLevel = categoryInfo != null ? categoryInfo.getSeverity() : "UNKNOWN";

							for (SootMethod method : foundMethods) {
								DangerousApiAnalysisResult apiAnalysisResult = new DangerousApiAnalysisResult(
										method.getSignature(), category, severityLevel);
								apkResult.addDangerousApiResult(apiAnalysisResult);
							}
						}

					} catch (IOException e) {
						System.err.println("Error loading dangerous API configuration: " + e.getMessage());
						e.printStackTrace();
						continue; // Skip this APK
					}

					// === CONSTRAINT ANALYSIS PHASE ===
					BackwardConstraintAnalyzer constraint_analyzer = new BackwardConstraintAnalyzer(graphAnalyzer,
							llm_config);
					constraint_analyzer.initialize();

					// Create and visualize the complete graph
					CompleteAllocationGraph completeGraph = new CompleteAllocationGraph(graphAnalyzer);
					completeGraph.visualizeGraph(fileNameDot, "dot");

					System.out.println("\n=== BACKWARD REACHABILITY ANALYSIS ===\n");

					// Get prioritized dangerous APIs instead of hardcoded sink
					List<SootMethod> dangerousApisToAnalyze = apiDetector.getPrioritizedDangerousApis(scanResult);

					if (dangerousApisToAnalyze.isEmpty()) {
						System.out.println("No analyzable dangerous APIs found");
						continue;
					}

					// Analyze each dangerous API
					for (SootMethod dangerousApi : dangerousApisToAnalyze) {
						// Find the corresponding result object
						DangerousApiAnalysisResult apiAnalysisResult = null;
						for (DangerousApiAnalysisResult result : apkResult.getDangerousApisFound()) {
							if (result.getMethodSignature().equals(dangerousApi.getSignature())) {
								apiAnalysisResult = result;
								break;
							}
						}

						if (apiAnalysisResult == null) {
							System.err
									.println("ERROR: Could not find result object for " + dangerousApi.getSignature());
							continue;
						}

						try {
							System.out.println("\n" + "=".repeat(80));
							System.out.println("ANALYZING DANGEROUS API: " + dangerousApi.getSignature());
							System.out.println("=".repeat(80));

							ConstraintAnalysisResult result = constraint_analyzer.analyzeMethod(dangerousApi);

							// === COLLECT ANALYSIS RESULTS ===

							// Extract call chains
							List<DangerousApiAnalysisResult.MethodCallChain> callChains = CallChainExtractor
									.extractCallChains(result, dangerousApi.getSignature());
							for (DangerousApiAnalysisResult.MethodCallChain callChain : callChains) {
								apiAnalysisResult.addCallChain(callChain);
							}

							// Extract constraints
							for (ConstraintPath path : result.getPaths()) {
								DangerousApiAnalysisResult.ConstraintSpecification constraint = new DangerousApiAnalysisResult.ConstraintSpecification(
										path.getPathId(), path.getPathId());

								// constraint.setBooleanLogicFormat(path.getPathSummary(ConstraintFormat.FORMAT_1));

								constraint
										.setBooleanLogicFormat(path.getCombinedConstraints(ConstraintFormat.FORMAT_1));
								// Add other formats if available
								constraint.setConstraintComplexity(path.getConstraints().size());

								apiAnalysisResult.addConstraint(constraint);
							}

							// Mark analysis as successful
							apiAnalysisResult.setAnalysisCompleted(true, null);

							for (ConstraintPath path : result.getPaths()) {
								System.out.println("=== Path: " + path.getPathId() + " ===");
								System.out.println(
										"Format 1 (Boolean Logic): " + path.getPathSummary(ConstraintFormat.FORMAT_1));
							}

							try {
								apkResult.setAnalysisCompleted(true, null);
								persistenceManager.saveApkAnalysisResult(apkResult);
								System.out.println("✅ Results saved for " + apkName);
							} catch (IOException e) {
								System.err.println(
										"ERROR: Failed to save results for " + apkName + ": " + e.getMessage());
							}

						} catch (Exception e) {
							System.err
									.println("Error analyzing " + dangerousApi.getSignature() + ": " + e.getMessage());

							// Mark analysis as failed
							apiAnalysisResult.setAnalysisCompleted(false, e.getMessage());
							continue; // Continue with next dangerous API
						}
					}

				} catch (Exception e) {
					System.err.println("Error during allocation analysis: " + e.getMessage());
					e.printStackTrace();
				} finally {
					// Cleanup for next APK
					try {
						if (Scene.v().hasCallGraph()) {
							Scene.v().releaseCallGraph();
						}
						Scene.v().releaseFastHierarchy();
						G.reset();
						System.gc(); // Suggest garbage collection between APKs
					} catch (Exception e) {
						System.err
								.println("WARNING: Cleanup failed after " + apkFile.getName() + ": " + e.getMessage());
					}
				}
			}
		} catch (AbortAnalysisException e) {
			// Silently return
		} catch (ParseException e) {
			formatter.printHelp("soot-infoflow-cmd [OPTIONS]", options);
			return;
		} catch (Exception e) {
			System.err.println(String.format("The data flow analysis has failed. Error message: %s", e.getMessage()));
			e.printStackTrace();
		}
	}

	private void printJimpleCode(SootMethod method) {
		System.out.println("\n=== Jimple Code for " + method.getSignature() + " ===\n");
		if (method.hasActiveBody()) {
			Body body = method.getActiveBody();
			System.out.println(body);
		}
	}

	private static String determineComponentType(SootClass clazz) {
		if (extendsClass(clazz, "android.app.Activity"))
			return "Activity";
		if (extendsClass(clazz, "android.app.Service"))
			return "Service";
		if (extendsClass(clazz, "android.content.BroadcastReceiver"))
			return "BroadcastReceiver";
		if (extendsClass(clazz, "android.content.ContentProvider"))
			return "ContentProvider";
		if (extendsClass(clazz, "android.app.Application"))
			return "Application";
		return "Unknown";
	}

	private static boolean extendsClass(SootClass clazz, String targetClassName) {
		try {
			SootClass current = clazz;
			while (current != null) {
				if (current.getName().equals(targetClassName)) {
					return true;
				}
				if (current.hasSuperclass()) {
					current = current.getSuperclass();
				} else {
					break;
				}
			}
		} catch (Exception e) {
			// Handle missing classes gracefully
		}
		return false;
	}

	private static boolean isFrameworkPackage(String packageName) {
		return packageName.startsWith("android.") ||
				packageName.startsWith("com.android.") ||
				packageName.startsWith("java.") ||
				packageName.startsWith("javax.") ||
				packageName.startsWith("com.google.android.") ||
				packageName.startsWith("com.facebook.") ||
				packageName.startsWith("com.paypal.") ||
				packageName.startsWith("ly.kite.") ||
				packageName.startsWith("io.card.") ||
				packageName.startsWith("com.stripe.") ||
				packageName.startsWith("com.crashlytics.") ||
				packageName.startsWith("com.appsflyer.");
	}

	// Batch processing statistics
	private static class BatchStatistics {
		public int totalApks = 0;
		public int successfulApks = 0;
		public int failedApks = 0;
		public Map<String, Integer> failureReasons = new HashMap<>();
		public List<String> successfulApkNames = new ArrayList<>();
		public List<String> failedApkNames = new ArrayList<>();

		public void recordSuccess(String apkName) {
			successfulApks++;
			successfulApkNames.add(apkName);
		}

		public void recordFailure(String apkName, String reason) {
			failedApks++;
			failedApkNames.add(apkName + " (" + reason + ")");
			failureReasons.merge(reason, 1, Integer::sum);
		}

		public void printSummary() {
			System.out.println("\n" + "=".repeat(80));
			System.out.println("               BATCH PROCESSING SUMMARY");
			System.out.println("=".repeat(80));
			System.out.println("Total APKs: " + totalApks);
			System.out.println("Successful: " + successfulApks);
			System.out.println("Failed: " + failedApks);
			System.out.println("Success Rate: " + String.format("%.1f%%", (successfulApks * 100.0 / totalApks)));

			if (!failureReasons.isEmpty()) {
				System.out.println("\nFailure Breakdown:");
				failureReasons.forEach((reason, count) -> System.out.println("  " + reason + ": " + count + " APKs"));
			}

			if (!failedApkNames.isEmpty()) {
				System.out.println("\nFailed APKs:");
				failedApkNames.forEach(name -> System.out.println("  - " + name));
			}
			System.out.println("=".repeat(80));
		}
	}

	private static String getRootPackage(String fullPackage) {
		String[] parts = fullPackage.split("\\.");
		if (parts.length >= 2) {
			return parts[0] + "." + parts[1]; // e.g., "com.prisma"
		}
		return fullPackage;
	}

	private static boolean isAppMethod(SootMethod method, Set<String> appPackagePrefixes) {
		String methodPackage = method.getDeclaringClass().getPackageName();
		for (String prefix : appPackagePrefixes) {
			if (methodPackage.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isLikelyEntryPoint(SootMethod method, String componentType) {
		String methodName = method.getName();

		// Skip constructors and static initializers for now
		if (methodName.equals("<init>") || methodName.equals("<clinit>")) {
			return false;
		}

		// Main pattern: methods starting with "on"
		if (methodName.startsWith("on")) {
			return true;
		}

		// Component-specific additional patterns
		if ("ContentProvider".equals(componentType)) {
			return methodName.equals("query") || methodName.equals("insert") ||
					methodName.equals("update") || methodName.equals("delete");
		}

		return false;
	}

	public void printAllEdges(Map<String, Set<String>> allEdges) {
		System.out.println("\n=== All Edges ===\n");
		for (Map.Entry<String, Set<String>> entry : allEdges.entrySet()) {
			printEdgesForNode(entry.getKey(), entry.getValue());
		}
	}

	public void printEdgesForNode(String fromNodeId, Set<String> toNodeIds) {
		for (String toNodeId : toNodeIds) {
			System.out.println(fromNodeId + " -> " + toNodeId);
		}
	}

	public String getPackageName(String apkPath) {
		String packageName = "";
		try {
			try (ProcessManifest manifest = new ProcessManifest(apkPath)) {
				packageName = manifest.getPackageName();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return packageName;
	}

	public Set<String> getEntryPoints(String apkPath) {
		Set<String> entryPointsClasses = new HashSet<String>();
		try {
			try (ProcessManifest manifest = new ProcessManifest(apkPath)) {
				entryPointsClasses = manifest.getEntryPointClasses();
			}
		} catch (IOException e) {
			System.err.println("Error reading manifest from APK: " + apkPath);
			e.printStackTrace();
		}
		return entryPointsClasses;
	}

	/**
	 * output the call graph to JSON format
	 * 
	 * @param cg
	 * @return String
	 */
	private String dumpCallGraph(CallGraph cg) {
		Iterator<Edge> itr = cg.iterator();
		Map<String, Set<String>> map = new HashMap<String, Set<String>>();

		while (itr.hasNext()) {
			Edge e = itr.next();
			String srcSig = e.getSrc().toString();
			String destSig = e.getTgt().toString();
			Set<String> neighborSet;
			if (map.containsKey(srcSig)) {
				neighborSet = map.get(srcSig);
			} else {
				neighborSet = new HashSet<String>();
			}
			neighborSet.add(destSig);
			map.put(srcSig, neighborSet);

		}

		Gson gson = new GsonBuilder().disableHtmlEscaping().create();
		return gson.toJson(map);
	}

	/**
	 *
	 * @param output
	 * @param packageName
	 */
	private void saveOutputToFile(String output, String packageName) {
		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
		String timestamp = now.format(formatter);

		String outputDir = System.getProperty("user.dir") + File.separator + "sootOutput";
		Path outputPath = Paths.get(outputDir, "cfg-" + packageName + "-" + timestamp + ".json");
		File out = outputPath.toFile();

		try {
			if (out.exists()) {
				out.delete();
			}
			FileWriter fw = new FileWriter(out);
			fw.write(output);
			fw.flush();
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates an instance of the FlowDroid data flow solver tool for Android.
	 * Derived classes can override this method to inject custom variants of
	 * FlowDroid.
	 * 
	 * @param config The configuration object
	 * @return An instance of the data flow solver
	 */
	protected SetupApplication createFlowDroidInstance(final InfoflowAndroidConfiguration config) {
		return new SetupApplication(config);
	}

	/**
	 * Initializes the taint wrapper based on the command-line parameters
	 * 
	 * @param cmd The command-line parameters
	 * @return The taint wrapper to use for the data flow analysis, or null in case
	 *         no taint wrapper shall be used
	 */
	private ITaintPropagationWrapper initializeTaintWrapper(CommandLine cmd) throws Exception {
		// If we want to analyze the full framework together with the app, we do not
		// want any shortcuts
		if (cmd.hasOption(OPTION_ANALYZE_FRAMEWORKS))
			return null;

		// Get the definition file(s) for the taint wrapper
		String[] definitionFiles = cmd.getOptionValues(OPTION_TAINT_WRAPPER_FILE);

		// If the user did not specify a taint wrapper, but definition files, we
		// use the most permissive option
		String taintWrapper = cmd.getOptionValue(OPTION_TAINT_WRAPPER);
		if (taintWrapper == null || taintWrapper.isEmpty()) {
			if (definitionFiles != null && definitionFiles.length > 0)
				taintWrapper = "multi";
			else {
				// If we don't have a taint wrapper configuration, we use the
				// default
				taintWrapper = "default";
			}
		}

		ITaintPropagationWrapper result = null;
		// Create the respective taint wrapper object
		switch (taintWrapper.toLowerCase()) {
			case "default":
				// We use StubDroid, but with the summaries from inside the JAR
				// files
				result = createSummaryTaintWrapper(cmd, new LazySummaryProvider("summariesManual"));
				break;
			case "defaultfallback":
				// We use StubDroid, but with the summaries from inside the JAR
				// files
				SummaryTaintWrapper summaryWrapper = createSummaryTaintWrapper(cmd,
						new LazySummaryProvider("summariesManual"));
				summaryWrapper.setFallbackTaintWrapper(EasyTaintWrapper.getDefault());
				result = summaryWrapper;
				break;
			case "none":
				break;
			case "easy":
				// If the user has not specified a definition file for the easy
				// taint wrapper, we try to locate a default file
				String defFile = null;
				if (definitionFiles == null || definitionFiles.length == 0) {
					File defaultFile = EasyTaintWrapper.locateDefaultDefinitionFile();
					if (defaultFile == null) {
						try {
							return new EasyTaintWrapper(defFile);
						} catch (Exception e) {
							e.printStackTrace();
							System.err.println(
									"No definition file for the easy taint wrapper specified and could not find the default file");
							throw new AbortAnalysisException();
						}
					} else
						defFile = defaultFile.getCanonicalPath();
				} else if (definitionFiles == null || definitionFiles.length != 1) {
					System.err.println("Must specify exactly one definition file for the easy taint wrapper");
					throw new AbortAnalysisException();
				} else
					defFile = definitionFiles[0];
				result = new EasyTaintWrapper(defFile);
				break;
			case "stubdroid":
				if (definitionFiles == null || definitionFiles.length == 0) {
					System.err.println("Must specify at least one definition file for StubDroid");
					throw new AbortAnalysisException();
				}
				result = TaintWrapperFactory.createTaintWrapper(Arrays.asList(definitionFiles));
				break;
			case "multi":
				// We need explicit definition files
				if (definitionFiles == null || definitionFiles.length == 0) {
					System.err.println("Must explicitly specify the definition files for the multi mode");
					throw new AbortAnalysisException();
				}

				// We need to group the definition files by their type
				MultiMap<String, String> extensionToFile = new HashMultiMap<>(definitionFiles.length);
				for (String str : definitionFiles) {
					File f = new File(str);
					if (f.isFile()) {
						String fileName = f.getName();
						extensionToFile.put(fileName.substring(fileName.lastIndexOf(".")), f.getCanonicalPath());
					} else if (f.isDirectory()) {
						extensionToFile.put(".xml", f.getCanonicalPath());
					}
				}

				// For each definition file, we create the respective taint wrapper
				TaintWrapperSet wrapperSet = new TaintWrapperSet();
				SummaryTaintWrapper stubDroidWrapper = null;
				if (extensionToFile.containsKey(".xml")) {
					stubDroidWrapper = TaintWrapperFactory.createTaintWrapper(extensionToFile.get(".xml"));
					wrapperSet.addWrapper(stubDroidWrapper);
				}
				Set<String> easyDefinitions = extensionToFile.get(".txt");
				if (!easyDefinitions.isEmpty()) {
					if (easyDefinitions.size() > 1) {
						System.err.println("Must specify exactly one definition file for the easy taint wrapper");
						throw new AbortAnalysisException();
					}

					// If we use StubDroid as well, we use the easy taint wrapper as
					// a fallback
					EasyTaintWrapper easyWrapper = new EasyTaintWrapper(easyDefinitions.iterator().next());
					if (stubDroidWrapper == null)
						wrapperSet.addWrapper(easyWrapper);
					else
						stubDroidWrapper.setFallbackTaintWrapper(easyWrapper);
				}
				result = wrapperSet;
				break;
			default:
				System.err.println("Invalid taint propagation wrapper specified, ignoring.");
				throw new AbortAnalysisException();
		}
		return result;

	}

	private SummaryTaintWrapper createSummaryTaintWrapper(CommandLine cmd, LazySummaryProvider lazySummaryProvider) {
		if (cmd.hasOption(OPTION_MISSING_SUMMARIES_FILE)) {
			reportMissingSummaryWrapper = new ReportMissingSummaryWrapper(lazySummaryProvider);
			return reportMissingSummaryWrapper;
		} else
			return new SummaryTaintWrapper(lazySummaryProvider);
	}

	private static CallgraphAlgorithm parseCallgraphAlgorithm(String algo) {
		if (algo.equalsIgnoreCase("AUTO"))
			return CallgraphAlgorithm.AutomaticSelection;
		else if (algo.equalsIgnoreCase("CHA"))
			return CallgraphAlgorithm.CHA;
		else if (algo.equalsIgnoreCase("VTA"))
			return CallgraphAlgorithm.VTA;
		else if (algo.equalsIgnoreCase("RTA"))
			return CallgraphAlgorithm.RTA;
		else if (algo.equalsIgnoreCase("SPARK"))
			return CallgraphAlgorithm.SPARK;
		else if (algo.equalsIgnoreCase("GEOM"))
			return CallgraphAlgorithm.GEOM;
		else {
			System.err.println(String.format("Invalid callgraph algorithm: %s", algo));
			throw new AbortAnalysisException();
		}
	}

	private static LayoutMatchingMode parseLayoutMatchingMode(String layoutMode) {
		if (layoutMode.equalsIgnoreCase("NONE"))
			return LayoutMatchingMode.NoMatch;
		else if (layoutMode.equalsIgnoreCase("PWD"))
			return LayoutMatchingMode.MatchSensitiveOnly;
		else if (layoutMode.equalsIgnoreCase("ALL"))
			return LayoutMatchingMode.MatchAll;
		else {
			System.err.println(String.format("Invalid layout matching mode: %s", layoutMode));
			throw new AbortAnalysisException();
		}
	}

	private static PathBuildingAlgorithm parsePathReconstructionAlgo(String pathAlgo) {
		if (pathAlgo.equalsIgnoreCase("CONTEXTSENSITIVE"))
			return PathBuildingAlgorithm.ContextSensitive;
		else if (pathAlgo.equalsIgnoreCase("CONTEXTINSENSITIVE"))
			return PathBuildingAlgorithm.ContextInsensitive;
		else if (pathAlgo.equalsIgnoreCase("SOURCESONLY"))
			return PathBuildingAlgorithm.ContextInsensitiveSourceFinder;
		else if (pathAlgo.equalsIgnoreCase("RECURSIVE"))
			return PathBuildingAlgorithm.Recursive;
		else {
			System.err.println(String.format("Invalid path reconstruction algorithm: %s", pathAlgo));
			throw new AbortAnalysisException();
		}
	}

	private static CallbackAnalyzer parseCallbackAnalyzer(String callbackAnalyzer) {
		if (callbackAnalyzer.equalsIgnoreCase("DEFAULT"))
			return CallbackAnalyzer.Default;
		else if (callbackAnalyzer.equalsIgnoreCase("FAST"))
			return CallbackAnalyzer.Fast;
		else {
			System.err.println(String.format("Invalid callback analysis algorithm: %s", callbackAnalyzer));
			throw new AbortAnalysisException();
		}
	}

	private static DataFlowSolver parseDataFlowSolver(String solver) {
		if (solver.equalsIgnoreCase("CONTEXTFLOWSENSITIVE"))
			return DataFlowSolver.ContextFlowSensitive;
		else if (solver.equalsIgnoreCase("FLOWINSENSITIVE"))
			return DataFlowSolver.FlowInsensitive;
		else if (solver.equalsIgnoreCase("GC"))
			return DataFlowSolver.GarbageCollecting;
		else if (solver.equalsIgnoreCase("FPC"))
			return DataFlowSolver.FineGrainedGC;
		else {
			System.err.println(String.format("Invalid data flow solver: %s", solver));
			throw new AbortAnalysisException();
		}
	}

	private static AliasingAlgorithm parseAliasAlgorithm(String aliasAlgo) {
		if (aliasAlgo.equalsIgnoreCase("NONE"))
			return AliasingAlgorithm.None;
		else if (aliasAlgo.equalsIgnoreCase("FLOWSENSITIVE"))
			return AliasingAlgorithm.FlowSensitive;
		else if (aliasAlgo.equalsIgnoreCase("PTSBASED"))
			return AliasingAlgorithm.PtsBased;
		else if (aliasAlgo.equalsIgnoreCase("LAZY"))
			return AliasingAlgorithm.Lazy;
		else {
			System.err.println(String.format("Invalid aliasing algorithm: %s", aliasAlgo));
			throw new AbortAnalysisException();
		}
	}

	private static CodeEliminationMode parseCodeEliminationMode(String eliminationMode) {
		if (eliminationMode.equalsIgnoreCase("NONE"))
			return CodeEliminationMode.NoCodeElimination;
		else if (eliminationMode.equalsIgnoreCase("PROPAGATECONSTS"))
			return CodeEliminationMode.PropagateConstants;
		else if (eliminationMode.equalsIgnoreCase("REMOVECODE"))
			return CodeEliminationMode.RemoveSideEffectFreeCode;
		else {
			System.err.println(String.format("Invalid code elimination mode: %s", eliminationMode));
			throw new AbortAnalysisException();
		}
	}

	private static CallbackSourceMode parseCallbackSourceMode(String callbackMode) {
		if (callbackMode.equalsIgnoreCase("NONE"))
			return CallbackSourceMode.NoParametersAsSources;
		else if (callbackMode.equalsIgnoreCase("ALL"))
			return CallbackSourceMode.AllParametersAsSources;
		else if (callbackMode.equalsIgnoreCase("SOURCELIST"))
			return CallbackSourceMode.SourceListOnly;
		else {
			System.err.println(String.format("Invalid callback source mode: %s", callbackMode));
			throw new AbortAnalysisException();
		}
	}

	private static PathReconstructionMode parsePathReconstructionMode(String pathReconstructionMode) {
		if (pathReconstructionMode.equalsIgnoreCase("NONE"))
			return PathReconstructionMode.NoPaths;
		else if (pathReconstructionMode.equalsIgnoreCase("FAST"))
			return PathReconstructionMode.Fast;
		else if (pathReconstructionMode.equalsIgnoreCase("PRECISE"))
			return PathReconstructionMode.Precise;
		else {
			System.err.println(String.format("Invalid path reconstruction mode: %s", pathReconstructionMode));
			throw new AbortAnalysisException();
		}
	}

	private static ImplicitFlowMode parseImplicitFlowMode(String implicitFlowMode) {
		if (implicitFlowMode.equalsIgnoreCase("NONE"))
			return ImplicitFlowMode.NoImplicitFlows;
		else if (implicitFlowMode.equalsIgnoreCase("ARRAYONLY"))
			return ImplicitFlowMode.ArrayAccesses;
		else if (implicitFlowMode.equalsIgnoreCase("ALL"))
			return ImplicitFlowMode.AllImplicitFlows;
		else {
			System.err.println(String.format("Invalid implicit flow mode: %s", implicitFlowMode));
			throw new AbortAnalysisException();
		}
	}

	private static StaticFieldTrackingMode parseStaticFlowMode(String staticFlowMode) {
		if (staticFlowMode.equalsIgnoreCase("NONE"))
			return StaticFieldTrackingMode.None;
		else if (staticFlowMode.equalsIgnoreCase("CONTEXTFLOWSENSITIVE"))
			return StaticFieldTrackingMode.ContextFlowSensitive;
		else if (staticFlowMode.equalsIgnoreCase("CONTEXTFLOWINSENSITIVE"))
			return StaticFieldTrackingMode.ContextFlowInsensitive;
		else {
			System.err.println(String.format("Invalid static flow tracking mode: %s", staticFlowMode));
			throw new AbortAnalysisException();
		}
	}

	private static DataFlowDirection parseDataFlowDirection(String dataflowDirection) {
		if (dataflowDirection.equalsIgnoreCase("FORWARDS"))
			return DataFlowDirection.Forwards;
		else if (dataflowDirection.equalsIgnoreCase("BACKWARDS"))
			return DataFlowDirection.Backwards;
		else {
			System.err.println(String.format("Invalid data flow direction: %s", dataflowDirection));
			throw new AbortAnalysisException();
		}
	}

	/**
	 * Parses the given command-line options and fills the given configuration
	 * object accordingly
	 * 
	 * @param cmd    The command line to parse
	 * @param config The configuration object to fill
	 */
	private void parseCommandLineOptions(CommandLine cmd, InfoflowAndroidConfiguration config) {
		// Files
		{
			String apkFile = cmd.getOptionValue(OPTION_APK_FILE);
			if (apkFile != null && !apkFile.isEmpty())
				config.getAnalysisFileConfig().setTargetAPKFile(new File(apkFile));
		}
		{
			String platformsDir = cmd.getOptionValue(OPTION_PLATFORMS_DIR);
			if (platformsDir != null && !platformsDir.isEmpty())
				config.getAnalysisFileConfig().setAndroidPlatformDir(new File(platformsDir));
		}
		{
			String sourcesSinks = cmd.getOptionValue(OPTION_SOURCES_SINKS_FILE);
			if (sourcesSinks != null && !sourcesSinks.isEmpty())
				config.getAnalysisFileConfig().setSourceSinkFile(new File(sourcesSinks));
		}
		{
			String outputFile = cmd.getOptionValue(OPTION_OUTPUT_FILE);
			if (outputFile != null && !outputFile.isEmpty())
				config.getAnalysisFileConfig().setOutputFile(outputFile);
		}
		{
			String additionalClasspath = cmd.getOptionValue(OPTION_ADDITIONAL_CLASSPATH);
			if (additionalClasspath != null && !additionalClasspath.isEmpty())
				config.getAnalysisFileConfig().setAdditionalClasspath(additionalClasspath);
		}
		if (cmd.hasOption(OPTION_WRITE_JIMPLE_FILES))
			config.setWriteOutputFiles(true);

		// Timeouts
		{
			Integer timeout = getIntOption(cmd, OPTION_TIMEOUT);
			if (timeout != null)
				config.setDataFlowTimeout(timeout);
		}
		{
			Integer timeout = getIntOption(cmd, OPTION_CALLBACK_TIMEOUT);
			if (timeout != null)
				config.getCallbackConfig().setCallbackAnalysisTimeout(timeout);
		}
		{
			Integer timeout = getIntOption(cmd, OPTION_RESULT_TIMEOUT);
			if (timeout != null)
				config.getPathConfiguration().setPathReconstructionTimeout(timeout);
		}

		// Optional features
		if (cmd.hasOption(OPTION_NO_STATIC_FLOWS))
			config.setStaticFieldTrackingMode(StaticFieldTrackingMode.None);
		if (cmd.hasOption(OPTION_NO_CALLBACK_ANALYSIS))
			config.getCallbackConfig().setEnableCallbacks(false);
		if (cmd.hasOption(OPTION_NO_EXCEPTIONAL_FLOWS))
			config.setEnableExceptionTracking(false);
		if (cmd.hasOption(OPTION_NO_TYPE_CHECKING))
			config.setEnableTypeChecking(false);
		if (cmd.hasOption(OPTION_REFLECTION))
			config.setEnableReflection(true);
		if (cmd.hasOption(OPTION_OUTPUT_LINENUMBERS))
			config.setEnableLineNumbers(true);
		if (cmd.hasOption(OPTION_ORIGINAL_NAMES))
			config.setEnableOriginalNames(true);
		// Individual settings
		{
			Integer aplength = getIntOption(cmd, OPTION_ACCESS_PATH_LENGTH);
			if (aplength != null)
				config.getAccessPathConfiguration().setAccessPathLength(aplength);
		}
		if (cmd.hasOption(OPTION_NO_THIS_CHAIN_REDUCTION))
			config.getAccessPathConfiguration().setUseThisChainReduction(false);
		if (cmd.hasOption(OPTION_FLOW_INSENSITIVE_ALIASING))
			config.setFlowSensitiveAliasing(false);
		if (cmd.hasOption(OPTION_COMPUTE_PATHS))
			config.getPathConfiguration().setPathReconstructionMode(PathReconstructionMode.Fast);
		if (cmd.hasOption(OPTION_ONE_SOURCE))
			config.setOneSourceAtATime(true);
		if (cmd.hasOption(OPTION_ONE_COMPONENT))
			config.setOneComponentAtATime(true);
		if (cmd.hasOption(OPTION_SEQUENTIAL_PATHS))
			config.getPathConfiguration().setSequentialPathProcessing(true);
		if (cmd.hasOption(OPTION_LOG_SOURCES_SINKS))
			config.setLogSourcesAndSinks(true);
		if (cmd.hasOption(OPTION_MERGE_DEX_FILES))
			config.setMergeDexFiles(true);
		if (cmd.hasOption(OPTION_PATH_SPECIFIC_RESULTS))
			config.setPathAgnosticResults(false);
		if (cmd.hasOption(OPTION_SINGLE_JOIN_POINT))
			config.getSolverConfiguration().setSingleJoinPointAbstraction(true);
		{
			Integer maxCallbacks = getIntOption(cmd, OPTION_MAX_CALLBACKS_COMPONENT);
			if (maxCallbacks != null)
				config.getCallbackConfig().setMaxCallbacksPerComponent(maxCallbacks);
		}
		{
			Integer maxDepth = getIntOption(cmd, OPTION_MAX_CALLBACKS_DEPTH);
			if (maxDepth != null)
				config.getCallbackConfig().setMaxAnalysisCallbackDepth(maxDepth);
		}
		{
			Integer maxthreadnum = getIntOption(cmd, OPTION_MAX_THREAD_NUMBER);
			if (maxthreadnum != null) {
				config.setMaxThreadNum(maxthreadnum);
			}
		}

		// Inter-component communication
		if (cmd.hasOption(OPTION_ICC_NO_PURIFY))
			config.getIccConfig().setIccResultsPurify(false);
		{
			String iccModel = cmd.getOptionValue(OPTION_ICC_MODEL);
			if (iccModel != null && !iccModel.isEmpty())
				config.getIccConfig().setIccModel(iccModel);
		}

		// Modes and algorithms
		{
			String cgalgo = cmd.getOptionValue(OPTION_CALLGRAPH_ALGO);
			if (cgalgo != null && !cgalgo.isEmpty())
				config.setCallgraphAlgorithm(parseCallgraphAlgorithm(cgalgo));
		}
		{
			String layoutMode = cmd.getOptionValue(OPTION_LAYOUT_MODE);
			if (layoutMode != null && !layoutMode.isEmpty())
				config.getSourceSinkConfig().setLayoutMatchingMode(parseLayoutMatchingMode(layoutMode));
		}
		{
			String pathAlgo = cmd.getOptionValue(OPTION_PATH_RECONSTRUCTION_ALGO);
			if (pathAlgo != null && !pathAlgo.isEmpty())
				config.getPathConfiguration().setPathBuildingAlgorithm(parsePathReconstructionAlgo(pathAlgo));
		}
		{
			String callbackAnalyzer = cmd.getOptionValue(OPTION_CALLBACK_ANALYZER);
			if (callbackAnalyzer != null && !callbackAnalyzer.isEmpty())
				config.getCallbackConfig().setCallbackAnalyzer(parseCallbackAnalyzer(callbackAnalyzer));
		}
		{
			String solver = cmd.getOptionValue(OPTION_DATA_FLOW_SOLVER);
			if (solver != null && !solver.isEmpty())
				config.getSolverConfiguration().setDataFlowSolver(parseDataFlowSolver(solver));
		}
		{
			String aliasAlgo = cmd.getOptionValue(OPTION_ALIAS_ALGO);
			if (aliasAlgo != null && !aliasAlgo.isEmpty())
				config.setAliasingAlgorithm(parseAliasAlgorithm(aliasAlgo));
		}
		{
			String eliminationMode = cmd.getOptionValue(OPTION_CODE_ELIMINATION_MODE);
			if (eliminationMode != null && !eliminationMode.isEmpty())
				config.setCodeEliminationMode(parseCodeEliminationMode(eliminationMode));
		}
		{
			String callbackMode = cmd.getOptionValue(OPTION_CALLBACK_SOURCE_MODE);
			if (callbackMode != null && !callbackMode.isEmpty())
				config.getSourceSinkConfig().setCallbackSourceMode(parseCallbackSourceMode(callbackMode));
		}
		{
			String pathMode = cmd.getOptionValue(OPTION_PATH_RECONSTRUCTION_MODE);
			if (pathMode != null && !pathMode.isEmpty())
				config.getPathConfiguration().setPathReconstructionMode(parsePathReconstructionMode(pathMode));
		}
		{
			String implicitMode = cmd.getOptionValue(OPTION_IMPLICIT_FLOW_MODE);
			if (implicitMode != null && !implicitMode.isEmpty())
				config.setImplicitFlowMode(parseImplicitFlowMode(implicitMode));
		}
		{
			String staticFlowMode = cmd.getOptionValue(OPTION_STATIC_FLOW_TRACKING_MODE);
			if (staticFlowMode != null && !staticFlowMode.isEmpty())
				config.setStaticFieldTrackingMode(parseStaticFlowMode(staticFlowMode));
		}
		{
			String dataflowDirection = cmd.getOptionValue(OPTION_DATA_FLOW_DIRECTION);
			if (dataflowDirection != null && !dataflowDirection.isEmpty())
				config.setDataFlowDirection(parseDataFlowDirection(dataflowDirection));
		}

		{
			String[] toSkip = cmd.getOptionValues(OPTION_SKIP_APK_FILE);
			if (toSkip != null && toSkip.length > 0) {
				for (String skipAPK : toSkip)
					filesToSkip.add(skipAPK);
			}
		}

		// We have some options to quickly configure FlowDroid for a certain mode or use
		// case
		if (cmd.hasOption(OPTION_ANALYZE_FRAMEWORKS)) {
			config.setExcludeSootLibraryClasses(false);
			config.setIgnoreFlowsInSystemPackages(false);
		}
		if (cmd.hasOption(OPTION_LENIENT_PARSING_MODE)) {
			ARSCFileParser.STRICT_MODE = false;
		}

		// Callgraph-specific options
		if (cmd.hasOption(OPTION_CALLGRAPH_ONLY))
			config.setTaintAnalysisEnabled(false);
		{
			String callgraphFile = cmd.getOptionValue(OPTION_CALLGRAPH_FILE);
			if (callgraphFile != null && !callgraphFile.isEmpty()) {
				config.getCallbackConfig().setSerializeCallbacks(true);
				config.getCallbackConfig().setCallbacksFile(callgraphFile);
			}
		}

		{
			Integer sleepTime = getIntOption(cmd, OPTION_GC_SLEEP_TIME);
			if (sleepTime != null) {
				config.getSolverConfiguration().setSleepTime(sleepTime);
			}
		}
	}

	private Integer getIntOption(CommandLine cmd, String option) {
		String str = cmd.getOptionValue(option);
		if (str == null || str.isEmpty())
			return null;
		else
			return Integer.parseInt(str);
	}

	/**
	 * Loads the data flow configuration from the given file
	 * 
	 * @param configFile The configuration file from which to load the data flow
	 *                   configuration
	 * @return The loaded data flow configuration
	 */
	private InfoflowAndroidConfiguration loadConfigurationFile(String configFile) {
		try {
			InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
			XMLConfigurationParser.fromFile(configFile).parse(config);
			return config;
		} catch (IOException e) {
			System.err.println("Could not parse configuration file: " + e.getMessage());
			return null;
		}
	}

}
