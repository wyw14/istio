// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"istio.io/istio/istioctl/pkg/analyze/baseline"
	"istio.io/istio/istioctl/pkg/cli"
	"istio.io/istio/istioctl/pkg/util"
	"istio.io/istio/istioctl/pkg/util/formatting"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/analysis"
	"istio.io/istio/pkg/config/analysis/analyzers"
	"istio.io/istio/pkg/config/analysis/diag"
	"istio.io/istio/pkg/config/analysis/local"
	"istio.io/istio/pkg/config/analysis/msg"
	"istio.io/istio/pkg/config/resource"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/multicluster"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/url"
)

// AnalyzerFoundIssuesError indicates that at least one analyzer found problems.
type AnalyzerFoundIssuesError struct{}

// FileParseError indicates a provided file was unable to be parsed.
type FileParseError struct{}

const FileParseString = "Some files couldn't be parsed."

func (f AnalyzerFoundIssuesError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Analyzers found issues when analyzing %s.\n", analyzeTargetAsString()))
	sb.WriteString(fmt.Sprintf("See %s for more information about causes and resolutions.", url.ConfigAnalysis))
	return sb.String()
}

func (f FileParseError) Error() string {
	return FileParseString
}

var (
	listAnalyzers     bool
	useKube           bool
	failureThreshold  = formatting.MessageThreshold{Level: diag.Error} // messages at least this level will generate an error exit code
	outputThreshold   = formatting.MessageThreshold{Level: diag.Info}  // messages at least this level will be included in the output
	colorize          bool
	msgOutputFormat   string
	meshCfgFile       string
	selectedNamespace string
	allNamespaces     bool
	suppress          []string
	analysisTimeout   time.Duration
	recursive         bool
	ignoreUnknown     bool
	revisionSpecified string
	remoteContexts    []string
	selectedAnalyzers []string
	baselineFile      string
	baselineExport    string

	fileExtensions = []string{".json", ".yaml", ".yml"}
)

// Analyze command
func Analyze(ctx cli.Context) *cobra.Command {
	var verbose bool
	analysisCmd := &cobra.Command{
		Use:   "analyze <file>...",
		Short: "Analyze Istio configuration and print validation messages",
		Long: fmt.Sprintf("Analyze Istio configuration and print validation messages.\n"+
			"For more information about message codes, refer to:\n%s", url.ConfigAnalysis),
		Example: `  # Analyze the current live cluster
  istioctl analyze

  # Analyze the current live cluster for a specific revision
  istioctl analyze --revision 1-16

  # Analyze the current live cluster, simulating the effect of applying additional yaml files
  istioctl analyze a.yaml b.yaml my-app-config/

  # Analyze yaml files without connecting to a live cluster
  istioctl analyze --use-kube=false a.yaml b.yaml my-app-config/

  # Analyze the current live cluster and suppress PodMissingProxy for pod mypod in namespace 'testing'.
  istioctl analyze -S "IST0103=Pod mypod.testing"

  # Analyze the current live cluster and suppress PodMissingProxy for all pods in namespace 'testing',
  # and suppress MisplacedAnnotation on deployment foobar in namespace default.
  istioctl analyze -S "IST0103=Pod *.testing" -S "IST0107=Deployment foobar.default"

  # List available analyzers
  istioctl analyze -L
  
  # Run specific analyzer
  istioctl analyze --analyzer "gateway.ConflictingGatewayAnalyzer"

  # Export the current diagnostics as a baseline for a cluster being remediated
  istioctl analyze --baseline-export analysis-baseline.yaml

  # Analyze against a baseline: only new or changed diagnostics fail the command
  istioctl analyze --baseline analysis-baseline.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			msgOutputFormat = strings.ToLower(msgOutputFormat)
			_, ok := formatting.MsgOutputFormats[msgOutputFormat]
			if !ok {
				return util.CommandParseError{
					Err: fmt.Errorf("%s not a valid option for format. See istioctl analyze --help", msgOutputFormat),
				}
			}

			if listAnalyzers {
				fmt.Print(AnalyzersAsString(analyzers.All()))
				return nil
			}

			if recursive {
				fmt.Println("The recursive flag has been removed and is hardcoded to true without explicitly specifying it.")
				return nil
			}

			if baselineFile != "" && baselineExport != "" {
				return util.CommandParseError{
					Err: fmt.Errorf("--baseline and --baseline-export cannot be used at the same time"),
				}
			}

			// Load the baseline before running any analysis: a malformed baseline
			// must fail loudly instead of silently behaving like an empty baseline.
			var baselineDoc *baseline.Baseline
			if baselineFile != "" {
				var loadErr error
				baselineDoc, loadErr = baseline.Load(baselineFile)
				if loadErr != nil {
					return loadErr
				}
			}

			readers, err := gatherFiles(cmd, args)
			if err != nil {
				return err
			}
			cancel := make(chan struct{})

			// We use the "namespace" arg that's provided as part of root istioctl as a flag for specifying what namespace to use
			// for file resources that don't have one specified.
			selectedNamespace = ctx.Namespace()
			if useKube {
				// apply default namespace if not specified and useKube is true
				selectedNamespace = ctx.NamespaceOrDefault(selectedNamespace)
				if selectedNamespace != "" {
					client, err := ctx.CLIClient()
					if err != nil {
						return err
					}
					_, err = client.Kube().CoreV1().Namespaces().Get(context.TODO(), selectedNamespace, metav1.GetOptions{})
					if errors.IsNotFound(err) {
						fmt.Fprintf(cmd.ErrOrStderr(), "namespace %q not found\n", ctx.Namespace())
						return nil
					} else if err != nil {
						return err
					}
				}
			}

			// If we've explicitly asked for all namespaces, blank the selectedNamespace var out
			// If the user hasn't specified a namespace, use the default namespace
			if allNamespaces {
				selectedNamespace = ""
			} else if selectedNamespace == "" {
				selectedNamespace = metav1.NamespaceDefault
			}

			combinedAnalyzers := analyzers.AllCombined()
			if len(selectedAnalyzers) != 0 {
				combinedAnalyzers = analyzers.NamedCombined(selectedAnalyzers...)
			}

			sa := local.NewIstiodAnalyzer(combinedAnalyzers,
				resource.Namespace(selectedNamespace),
				resource.Namespace(ctx.IstioNamespace()), nil)

			// Check for suppressions and add them to our SourceAnalyzer
			suppressions := make([]local.AnalysisSuppression, 0, len(suppress))
			for _, s := range suppress {
				parts := strings.Split(s, "=")
				if len(parts) != 2 {
					return fmt.Errorf("%s is not a valid suppression value. See istioctl analyze --help", s)
				}
				// Check to see if the supplied code is valid. If not, emit a
				// warning but continue.
				codeIsValid := false
				for _, at := range msg.All() {
					if at.Code() == parts[0] {
						codeIsValid = true
						break
					}
				}

				if !codeIsValid {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: Supplied message code '%s' is an unknown message code and will not have any effect.\n", parts[0])
				}
				suppressions = append(suppressions, local.AnalysisSuppression{
					Code:         parts[0],
					ResourceName: parts[1],
				})
			}
			sa.SetSuppressions(suppressions)

			shouldPrintCluster := false
			// If we're using kube, use that as a base source.
			if useKube {
				clients, err := getClients(ctx)
				if err != nil {
					return err
				}
				// If there are multiple clients, we think it's a multi-cluster scenario.
				if len(clients) > 1 {
					shouldPrintCluster = true
				}
				for _, c := range clients {
					k := kube.EnableCrdWatcher(c.client)
					sa.AddRunningKubeSourceWithRevision(k, revisionSpecified, c.remote)
				}
			}

			// If we explicitly specify mesh config, use it.
			// This takes precedence over default mesh config or mesh config from a running Kube instance.
			if meshCfgFile != "" {
				if err := sa.AddFileKubeMeshConfig(meshCfgFile); err != nil {
					return fmt.Errorf("failed to load mesh config file %q: %w", meshCfgFile, err)
				}
			}

			// If we're not using kube (files only), add defaults for some resources we expect to be provided by Istio
			if !useKube {
				err := sa.AddDefaultResources()
				if err != nil {
					return err
				}
			}

			// If files are provided, treat them (collectively) as a source.
			parseErrors := 0
			if len(readers) > 0 {
				if err = sa.AddReaderKubeSource(readers); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Error(s) adding files: %v", err)
					parseErrors++
				}
			}

			// Do the analysis
			result, err := sa.Analyze(cancel)
			if err != nil {
				return err
			}

			// Maybe output details about which analyzers ran
			if verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "Analyzed resources in %s\n", analyzeTargetAsString())

				if len(result.SkippedAnalyzers) > 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "Skipped analyzers:")
					for _, a := range result.SkippedAnalyzers {
						fmt.Fprintln(cmd.ErrOrStderr(), "\t", a)
					}
				}
				if len(result.ExecutedAnalyzers) > 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "Executed analyzers:")
					for _, a := range result.ExecutedAnalyzers {
						fmt.Fprintln(cmd.ErrOrStderr(), "\t", a)
					}
				}
				fmt.Fprintln(cmd.ErrOrStderr())
			}

			// Explicitly export the current diagnostics as a baseline and stop:
			// new diagnostics are never added to a baseline automatically.
			if baselineExport != "" {
				return exportBaseline(cmd, result.Messages, parseErrors)
			}

			// Classify diagnostics against the baseline, if one was provided.
			var baselineReport *baseline.Report
			if baselineDoc != nil {
				r := baseline.Classify(baselineDoc, result.Messages, time.Now().UTC())
				baselineReport = &r
			}

			result.Messages.SetDocRef("istioctl-analyze")

			// activeMessages are the diagnostics that are not accepted by the
			// baseline; only they drive regular output and the exit code.
			activeMessages := result.Messages
			var knownMessages diag.Messages
			if baselineReport != nil {
				activeMessages = baselineReport.New
				knownMessages = baselineReport.Known
			}

			if shouldPrintCluster {
				setPrintCluster(activeMessages)
				setPrintCluster(knownMessages)
			}

			// Get messages for output
			outputMessages := activeMessages.FilterOutLowerThan(outputThreshold.Level)
			knownOutputMessages := knownMessages.FilterOutLowerThan(outputThreshold.Level)

			if baselineReport == nil {
				// Print all the messages to stdout in the specified format
				output, err := formatting.Print(outputMessages, msgOutputFormat, colorize)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), output)
			} else {
				if err := printBaselineResult(cmd, baselineReport, outputMessages, knownOutputMessages); err != nil {
					return err
				}
			}

			// An extra message on success
			if baselineReport == nil {
				if len(outputMessages) == 0 {
					if parseErrors == 0 {
						if len(readers) > 0 {
							var files []string
							for _, r := range readers {
								files = append(files, r.Name)
							}
							if len(files) > 1 {
								fmt.Fprintf(cmd.ErrOrStderr(), "\u2714 No validation issues found when analyzing:\n  - %s\n", strings.Join(files, "\n  - "))
							} else {
								fmt.Fprintf(cmd.ErrOrStderr(), "\u2714 No validation issues found when analyzing %s.\n", strings.Join(files, "\n"))
							}
						} else {
							fmt.Fprintf(cmd.ErrOrStderr(), "\u2714 No validation issues found when analyzing %s.\n", analyzeTargetAsString())
						}
					} else {
						fileOrFiles := "files"
						if parseErrors == 1 {
							fileOrFiles = "file"
						}
						fmt.Fprintf(cmd.ErrOrStderr(),
							"No validation issues found when analyzing %s (but %d %s could not be parsed).\n",
							analyzeTargetAsString(),
							parseErrors,
							fileOrFiles,
						)
					}
				}
			} else {
				writeBaselineSummary(cmd.ErrOrStderr(), baselineReport)
				if len(activeMessages) == 0 {
					if parseErrors == 0 {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"\u2714 No new validation issues found when analyzing %s (%d known diagnostic(s) accepted by the baseline).\n",
							analyzeTargetAsString(), len(baselineReport.Known))
					} else {
						fileOrFiles := "files"
						if parseErrors == 1 {
							fileOrFiles = "file"
						}
						fmt.Fprintf(cmd.ErrOrStderr(),
							"No new validation issues found when analyzing %s, but %d %s could not be parsed.\n",
							analyzeTargetAsString(), parseErrors, fileOrFiles)
					}
				}
			}

			// Return code is based on the unfiltered validation message list/parse errors
			// We're intentionally keeping failure threshold and output threshold decoupled for now.
			// When a baseline is in use, only diagnostics it does not accept can fail the command.
			var returnError error
			if msgOutputFormat == formatting.LogFormat {
				returnError = errorIfMessagesExceedThreshold(activeMessages)
				if returnError == nil && parseErrors > 0 && !ignoreUnknown {
					returnError = FileParseError{}
				}
			}
			return returnError
		},
	}

	analysisCmd.PersistentFlags().BoolVarP(&listAnalyzers, "list-analyzers", "L", false,
		"List the analyzers available to run. Suppresses normal execution.")
	analysisCmd.PersistentFlags().BoolVarP(&useKube, "use-kube", "k", true,
		"Use live Kubernetes cluster for analysis. Set --use-kube=false to analyze files only.")
	analysisCmd.PersistentFlags().BoolVar(&colorize, "color", formatting.IstioctlColorDefault(analysisCmd.OutOrStdout()),
		"Default true.  Disable with '=false' or set $TERM to dumb")
	analysisCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")
	analysisCmd.PersistentFlags().Var(&failureThreshold, "failure-threshold",
		fmt.Sprintf("The severity level of analysis at which to set a non-zero exit code. Valid values: %v", diag.GetAllLevelStrings()))
	analysisCmd.PersistentFlags().Var(&outputThreshold, "output-threshold",
		fmt.Sprintf("The severity level of analysis at which to display messages. Valid values: %v", diag.GetAllLevelStrings()))
	analysisCmd.PersistentFlags().StringVarP(&msgOutputFormat, "output", "o", formatting.LogFormat,
		fmt.Sprintf("Output format: one of %v", formatting.MsgOutputFormatKeys))
	analysisCmd.PersistentFlags().StringVar(&meshCfgFile, "meshConfigFile", "",
		"Overrides the mesh config values to use for analysis.")
	analysisCmd.PersistentFlags().BoolVarP(&allNamespaces, "all-namespaces", "A", false,
		"Analyze all namespaces")
	analysisCmd.PersistentFlags().StringArrayVarP(&suppress, "suppress", "S", []string{},
		"Suppress reporting a message code on a specific resource. Values are supplied in the form "+
			`<code>=<resource> (e.g. '--suppress "IST0102=DestinationRule primary-dr.default"'). Can be repeated. `+
			`You can include the wildcard character '*' to support a partial match (e.g. '--suppress "IST0102=DestinationRule *.default" ).`)
	analysisCmd.PersistentFlags().DurationVar(&analysisTimeout, "timeout", 30*time.Second,
		"The duration to wait before failing")
	analysisCmd.PersistentFlags().BoolVarP(&recursive, "recursive", "R", false,
		"[Removed: The recursive flag has been removed and is hardcoded to true] Process directory arguments recursively.")
	analysisCmd.PersistentFlags().BoolVar(&ignoreUnknown, "ignore-unknown", false,
		"Don't complain about un-parseable input documents, for cases where analyze should run only on k8s compliant inputs.")
	analysisCmd.PersistentFlags().StringVarP(&revisionSpecified, "revision", "r", "default",
		"analyze a specific revision deployed.")
	analysisCmd.PersistentFlags().StringArrayVar(&remoteContexts, "remote-contexts", []string{},
		`Kubernetes configuration contexts for remote clusters to be used in multi-cluster analysis. Not to be confused with '--context'. `+
			"If unspecified, contexts are read from the remote secrets in the cluster.")
	analysisCmd.PersistentFlags().StringArrayVarP(&selectedAnalyzers, "analyzer", "", []string{},
		"Select specific analyzers to run. Can be repeated. If not specified, all analyzers are run. "+
			"(e.g. istioctl analyze --analyzer \"gateway.ConflictingGatewayAnalyzer\")")
	analysisCmd.PersistentFlags().StringVar(&baselineFile, "baseline", "",
		"Use a diagnostic baseline file created with --baseline-export. Diagnostics identical to an unexpired "+
			"baseline entry (same message code, severity, resource, cluster and message parameters; line numbers "+
			"and ordering are ignored) are marked as known and do not trigger the failure threshold. New, "+
			"disappeared and expired entries are summarized. A missing or malformed baseline file fails the command.")
	analysisCmd.PersistentFlags().StringVar(&baselineExport, "baseline-export", "",
		"Export the current diagnostics to a baseline file and exit. The file can later be passed to --baseline "+
			"so that only diagnostics that are new or changed fail the command. Diagnostics without a reliable "+
			"resource identity are not exported, and new diagnostics are never added to a baseline automatically.")
	return analysisCmd
}

func gatherFiles(cmd *cobra.Command, args []string) ([]local.ReaderSource, error) {
	var readers []local.ReaderSource
	for _, f := range args {
		var r *os.File

		// Handle "-" as stdin as a special case.
		if f == "-" {
			if isatty.IsTerminal(os.Stdin.Fd()) && !isJSONorYAMLOutputFormat() {
				fmt.Fprint(cmd.OutOrStdout(), "Reading from stdin:\n")
			}
			r = os.Stdin
			readers = append(readers, local.ReaderSource{Name: f, Reader: r})
			continue
		}

		fi, err := os.Stat(f)
		if err != nil {
			return nil, err
		}

		if fi.IsDir() {
			dirReaders, err := gatherFilesInDirectory(cmd, f)
			if err != nil {
				return nil, err
			}
			readers = append(readers, dirReaders...)
		} else {
			if !isValidFile(f) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Skipping file %v, recognized file extensions are: %v\n", f, fileExtensions)
				continue
			}
			rs, err := gatherFile(f)
			if err != nil {
				return nil, err
			}
			readers = append(readers, rs)
		}
	}
	return readers, nil
}

func gatherFile(f string) (local.ReaderSource, error) {
	r, err := os.Open(f)
	if err != nil {
		return local.ReaderSource{}, err
	}
	runtime.SetFinalizer(r, func(x *os.File) {
		err = x.Close()
		if err != nil {
			log.Infof("file : %s is not closed: %v", f, err)
		}
	})
	return local.ReaderSource{Name: f, Reader: r}, nil
}

func gatherFilesInDirectory(cmd *cobra.Command, dir string) ([]local.ReaderSource, error) {
	var readers []local.ReaderSource

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !isValidFile(path) {
			fmt.Fprintf(cmd.ErrOrStderr(), "Skipping file %v, recognized file extensions are: %v\n", path, fileExtensions)
			return nil
		}

		r, err := os.Open(path)
		if err != nil {
			return err
		}
		runtime.SetFinalizer(r, func(x *os.File) {
			err = x.Close()
			if err != nil {
				log.Infof("file: %s is not closed: %v", path, err)
			}
		})
		readers = append(readers, local.ReaderSource{Name: path, Reader: r})
		return nil
	})
	return readers, err
}

func errorIfMessagesExceedThreshold(messages []diag.Message) error {
	foundIssues := false
	for _, m := range messages {
		if m.Type.Level().IsWorseThanOrEqualTo(failureThreshold.Level) {
			foundIssues = true
		}
	}

	if foundIssues {
		return AnalyzerFoundIssuesError{}
	}

	return nil
}

func setPrintCluster(messages diag.Messages) {
	for i := range messages {
		m := &messages[i]
		if m.Resource != nil && m.Resource.Origin.ClusterName().String() != "" {
			m.PrintCluster = true
		}
	}
}

// exportBaseline writes the current diagnostics to the requested baseline file
// and exits. It never augments an existing baseline with new findings: the
// export is always derived solely from the diagnostics just produced.
func exportBaseline(cmd *cobra.Command, messages diag.Messages, parseErrors int) error {
	doc, skipped := baseline.FromMessages(messages, time.Now().UTC())
	if err := baseline.WriteFile(baselineExport, doc); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Exported %d diagnostic(s) to baseline file %q.\n", len(doc.Entries), baselineExport)
	if skipped > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: %d diagnostic(s) without a reliable resource identity were not exported and will still fail future analyses.\n",
			skipped)
	}
	if parseErrors > 0 && !ignoreUnknown {
		return FileParseError{}
	}
	return nil
}

// printBaselineResult renders new and known diagnostics plus the baseline
// summary in the requested output format.
func printBaselineResult(cmd *cobra.Command, report *baseline.Report, newMessages, knownMessages diag.Messages) error {
	switch msgOutputFormat {
	case formatting.LogFormat:
		if len(newMessages) > 0 {
			output, err := formatting.Print(newMessages, formatting.LogFormat, colorize)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), output)
		}
		if len(knownMessages) > 0 {
			output, err := formatting.Print(knownMessages, formatting.LogFormat, colorize)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(),
				"Known diagnostics (accepted by the baseline, not counted towards the failure threshold):")
			for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", line)
			}
		}
	case formatting.JSONFormat, formatting.YAMLFormat:
		output, err := marshalBaselineMachineOutput(report, newMessages, knownMessages, msgOutputFormat)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), output)
	default:
		return fmt.Errorf("%s not a valid option for format. See istioctl analyze --help", msgOutputFormat)
	}
	return nil
}

func writeBaselineSummary(w io.Writer, r *baseline.Report) {
	fmt.Fprintf(w, "Baseline summary: %d new, %d known, %d disappeared, %d expired.\n",
		len(r.New), len(r.Known), len(r.Disappeared), len(r.Expired))
	if len(r.Disappeared) > 0 {
		fmt.Fprintln(w, "Disappeared baseline entries (no longer reported):")
		for _, e := range r.Disappeared {
			fmt.Fprintf(w, "  - %s\n", e.String())
		}
	}
	if len(r.Expired) > 0 {
		fmt.Fprintln(w, "Expired baseline entries (diagnostics are reported normally again):")
		for _, e := range r.Expired {
			fmt.Fprintf(w, "  - %s\n", e.String())
		}
	}
}

// annotatedDiagnostic is a diagnostic carrying its baseline classification in
// JSON/YAML output.
type annotatedDiagnostic struct {
	message        diag.Message
	baselineStatus string
}

func (a annotatedDiagnostic) MarshalJSON() ([]byte, error) {
	unstructured := a.message.Unstructured(true)
	unstructured["baselineStatus"] = a.baselineStatus
	return json.Marshal(unstructured)
}

type baselineMachineOutput struct {
	Messages       []annotatedDiagnostic `json:"messages" yaml:"messages"`
	BaselineReport baselineSummaryOutput `json:"baselineReport" yaml:"baselineReport"`
}

type baselineSummaryOutput struct {
	New         int              `json:"new" yaml:"new"`
	Known       []baseline.Entry `json:"known" yaml:"known"`
	Disappeared []baseline.Entry `json:"disappeared" yaml:"disappeared"`
	Expired     []baseline.Entry `json:"expired" yaml:"expired"`
}

func marshalBaselineMachineOutput(report *baseline.Report, newMessages, knownMessages diag.Messages, format string) (string, error) {
	out := baselineMachineOutput{
		BaselineReport: baselineSummaryOutput{
			New:         len(report.New),
			Known:       entriesForMessages(report.Known),
			Disappeared: report.Disappeared,
			Expired:     report.Expired,
		},
		Messages: make([]annotatedDiagnostic, 0, len(newMessages)+len(knownMessages)),
	}
	if out.BaselineReport.Disappeared == nil {
		out.BaselineReport.Disappeared = []baseline.Entry{}
	}
	if out.BaselineReport.Expired == nil {
		out.BaselineReport.Expired = []baseline.Entry{}
	}
	for _, m := range newMessages {
		out.Messages = append(out.Messages, annotatedDiagnostic{message: m, baselineStatus: "new"})
	}
	for _, m := range knownMessages {
		out.Messages = append(out.Messages, annotatedDiagnostic{message: m, baselineStatus: "known"})
	}
	if format == formatting.JSONFormat {
		buf, err := json.MarshalIndent(out, "", "\t")
		return string(buf), err
	}
	buf, err := yaml.Marshal(out)
	return string(buf), err
}

func entriesForMessages(messages diag.Messages) []baseline.Entry {
	if len(messages) == 0 {
		return []baseline.Entry{}
	}
	entries := make([]baseline.Entry, 0, len(messages))
	for _, m := range messages {
		if e, ok := baseline.EntryFromMessage(m); ok {
			entries = append(entries, e)
		}
	}
	return entries
}

func isValidFile(f string) bool {
	ext := filepath.Ext(f)
	for _, e := range fileExtensions {
		if e == ext {
			return true
		}
	}
	return false
}

func AnalyzersAsString(analyzers []analysis.Analyzer) string {
	nameToAnalyzer := make(map[string]analysis.Analyzer)
	analyzerNames := make([]string, len(analyzers))
	for i, a := range analyzers {
		analyzerNames[i] = a.Metadata().Name
		nameToAnalyzer[a.Metadata().Name] = a
	}
	sort.Strings(analyzerNames)

	var b strings.Builder
	for _, aName := range analyzerNames {
		b.WriteString(fmt.Sprintf("* %s:\n", aName))
		a := nameToAnalyzer[aName]
		if a.Metadata().Description != "" {
			b.WriteString(fmt.Sprintf("    %s\n", a.Metadata().Description))
		}
	}
	return b.String()
}

func analyzeTargetAsString() string {
	if allNamespaces {
		return "all namespaces"
	}
	return fmt.Sprintf("namespace: %s", selectedNamespace)
}

// TODO: Refactor output writer so that it is smart enough to know when to output what.
func isJSONorYAMLOutputFormat() bool {
	return msgOutputFormat == formatting.JSONFormat || msgOutputFormat == formatting.YAMLFormat
}

type Client struct {
	client kube.Client
	remote bool
}

func getClients(ctx cli.Context) ([]*Client, error) {
	client, err := ctx.CLIClient()
	if err != nil {
		return nil, err
	}
	clients := []*Client{
		{
			client: client,
			remote: false,
		},
	}
	if len(remoteContexts) > 0 {
		remoteClients, err := getClientsFromContexts(ctx)
		if err != nil {
			return nil, err
		}
		clients = append(clients, remoteClients...)
		return clients, nil
	}
	secrets, err := client.Kube().CoreV1().Secrets(ctx.IstioNamespace()).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", multicluster.MultiClusterSecretLabel, "true"),
	})
	if err != nil {
		return nil, err
	}
	for _, s := range secrets.Items {
		for _, cfg := range s.Data {
			// Secrets in this namespace are untrusted input from the perspective of this
			// process, exactly as istiod treats them in DefaultBuildClientsFromConfig. Sanitize
			// the kubeconfig - rejecting exec, file-based, or other unsafe auth - and build the
			// client from the sanitized rest.Config itself, not from the original bytes, so a
			// gap between what's validated and what's used can't reopen this.
			restConfig, err := kube.NewUntrustedRestConfig(cfg)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig in secret %s/%s is not allowed: %v", s.Namespace, s.Name, err)
			}
			rawConfig, err := clientcmd.Load(cfg)
			if err != nil {
				return nil, err
			}
			curContext := rawConfig.Contexts[rawConfig.CurrentContext]
			if curContext == nil {
				continue
			}
			client, err := kube.NewCLIClient(kube.NewClientConfigForRestConfig(restConfig),
				kube.WithRevision(revisionSpecified),
				kube.WithCluster(cluster.ID(curContext.Cluster)))
			if err != nil {
				return nil, err
			}
			clients = append(clients, &Client{
				client: client,
				remote: true,
			})
		}
	}
	return clients, nil
}

func getClientsFromContexts(ctx cli.Context) ([]*Client, error) {
	var clients []*Client
	remoteClients, err := ctx.CLIClientsForContexts(remoteContexts)
	if err != nil {
		return nil, err
	}
	for _, c := range remoteClients {
		clients = append(clients, &Client{
			client: c,
			remote: true,
		})
	}
	return clients, nil
}
