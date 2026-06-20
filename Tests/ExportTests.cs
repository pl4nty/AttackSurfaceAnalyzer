// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using Microsoft.CST.AttackSurfaceAnalyzer.Cli;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.OAT;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class ExportTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        /// <summary>
        ///     Does not require admin.
        /// </summary>
        [TestMethod]
        public void TestGenerateSarifLog()
        {
            JsonSerializerSettings jsonSettings = new()
            {
                Formatting = Formatting.Indented, 
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                DateFormatHandling = DateFormatHandling.IsoDateFormat
            };

            Dictionary<string, string> metadata = new Dictionary<string, string>()
            {
                { "compare-version", "2.4.10-alpha+5351e91d1c" },
                { "compare-os", "WINDOWS" },
                { "compare-osversion", "Microsoft Windows NT 10.0.19043.0" },
                {
                    "analyses-hash",
                    "yXvUiHy+rkKstAubfKrepSYhf7tGW6Fmpq72cvzjHu/IFkPu1P6FEstdy15fnGvxhAyIcIzdWFTILRTZ6wy0yA=="
                }
            };
            Dictionary<string, ConcurrentBag<CompareResult>> output = new()
            {
                {
                    "FILE_CREATED", new ConcurrentBag<CompareResult>()
                    {
                        new()
                        {
                            Analysis = ANALYSIS_RESULT_TYPE.DEBUG,
                            BaseRunId = "2021-10-14T16:40:08.6642182-07:00",
                            Compare = new FileSystemObject("C:\\Test\\Scan2\\TestAddText.txt")
                            {
                                ContentHash =
                                    "U5vuoQXdbgnk9XHXG35PFwb90oyl1iXPq63NYaMrIqpkQVU6X+ntJF7D57ZJFufpTXgPvR2zgqZu/anwz+wd2Q==",
                                Created = DateTime.Parse("2021-10-14T23:41:18.3939762Z"),
                                Group = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                LastModified = DateTime.Parse("2021-10-14T23:43:53.0879739Z"),
                                Owner = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "S-1-5-11", "Modify, Synchronize" },
                                    { "S-1-5-18", "FullControl" },
                                    { "S-1-5-32-544", "FullControl" },
                                    { "S-1-5-32-545", "ReadAndExecute, Synchronize" }
                                },
                                Size = 19,
                            },
                            CompareRunId = "2021-10-14T16:44:27.3260573-07:00",
                            AnalysesHash =
                                "yXvUiHy+rkKstAubfKrepSYhf7tGW6Fmpq72cvzjHu/IFkPu1P6FEstdy15fnGvxhAyIcIzdWFTILRTZ6wy0yA=="
                        },
                        new()
                        {
                            Analysis = ANALYSIS_RESULT_TYPE.DEBUG,
                            BaseRunId = "2021-10-14T16:40:08.6642182-07:00",
                            Compare = new FileSystemObject("C:\\Test\\Scan2\\TestAddExe.exe")
                            {
                                ContentHash =
                                    "3ptaDfkOhjUOM6QE2HoSCAasWmp9TR77AZVXRHniF8tWDXj1YT0rrjcxQAQmpOnxh31uVxfk0hqPyBbPWddeyA==",
                                Created = DateTime.Parse("2021-10-14T23:40:20.957942Z"),
                                Group = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                IsExecutable = true,
                                LastModified = DateTime.Parse("2021-10-13T03:05:24.3286411Z"),
                                Owner = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "S-1-5-11", "Modify, Synchronize" },
                                    { "S-1-5-18", "FullControl" },
                                    { "S-1-5-32-544", "FullControl" },
                                    { "S-1-5-32-545", "ReadAndExecute, Synchronize" }
                                },
                                Size = 726896
                            },
                            CompareRunId = "2021-10-14T16:44:27.3260573-07:00",
                            AnalysesHash =
                                "yXvUiHy+rkKstAubfKrepSYhf7tGW6Fmpq72cvzjHu/IFkPu1P6FEstdy15fnGvxhAyIcIzdWFTILRTZ6wy0yA==",
                            Rules = [
                                new AsaRule("Missing DEP"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.WINDOWS
                                  ],
                                  Clauses = [
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "EXE",
                                      Arguments = []
                                    },
                                    new Clause(Operation.Contains){
                                      Data = [
                                        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"
                                      ],
                                      DictData = [],
                                      Field = "Characteristics",
                                      Label = "DEP",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when executables are created without DEP.",
                                  Expression = "EXE AND NOT DEP",
                                  Target = "FileSystemObject",
                                  Flag = ANALYSIS_RESULT_TYPE.WARNING,
                                  Tags = []
                                },
                                new AsaRule("Missing ASLR"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.WINDOWS
                                  ],
                                  Clauses = [
                                    new  Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "EXE",
                                      Arguments = []
                                    },
                                    new Clause(Operation.Contains){
                                      Data = [
                                        "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                                        "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"
                                      ],
                                      DictData = [],
                                      Field = "Characteristics",
                                      Label = "ASLR",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when executables are created without ASLR.",
                                  Expression = "EXE AND NOT ASLR",
                                  Target = "FileSystemObject",
                                  Flag=ANALYSIS_RESULT_TYPE.WARNING,
                                  Tags = []
                                },
                                new AsaRule("Unsigned binaries"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.WINDOWS, PLATFORM.LINUX, PLATFORM.MACOS
                                  ],
                                  Clauses = [
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "is_exe",
                                      Arguments = []
                                    },
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "SignatureStatus.IsAuthenticodeValid",
                                      Label = "valid_windows_signature",
                                      Arguments = []
                                    },
                                    new Clause(Operation.IsNull){
                                      Data = [],
                                      DictData = [],
                                      Field = "MacSignatureStatus",
                                      Label = "null_mac_signature",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when unsigned/incorrectly signed binaries are added.",
                                  Expression = "is_exe AND NOT valid_windows_signature AND null_mac_signature",
                                  Target = "FileSystemObject",
                                  Tags = [],
                                  Flag = ANALYSIS_RESULT_TYPE.WARNING
                                }
                            ]
                        }
                    }
                },
                {
                    "FILE_MODIFIED", new ConcurrentBag<CompareResult>()
                    {
                        new()
                        {
                            Analysis = ANALYSIS_RESULT_TYPE.WARNING,
                            Base = new FileSystemObject("C:\\Test\\Scan2\\TestModifyExe.exe")
                            {
                                ContentHash = "7QGAoQeCLD64FeGxlSoeW5eHcACmyBrT1HIv+YOGVi2Of6c88DR6+Uk1O2zemHCGXAeJrtc+COi8yqHrnpX8Zg==",
                                Created = DateTime.Parse("2021-10-14T23:36:58.0340629Z"),
                                Group = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                IsExecutable = true,
                                LastModified = DateTime.Parse("2021-10-13T03:05:24.3286411Z"),
                                Owner = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "S-1-5-11", "Modify, Synchronize" },
                                    { "S-1-5-18", "FullControl" },
                                    { "S-1-5-32-544", "FullControl" },
                                    { "S-1-5-32-545", "ReadAndExecute, Synchronize" }
                                },
                                Size = 726896
                            },
                            BaseRunId = "2021-10-14T16:40:08.6642182-07:00",
                            Compare = new FileSystemObject("C:\\Test\\Scan2\\TestModifyExe.exe")
                            {
                                ContentHash = "Qpr6h4sgWi9HvNaKn1kWmznUifwU+8Uw6RjczVpkzx/LlGSyJgEhQ9pkMe6sX3wo9gwLmZicOIelU2b9NncLiw==",
                                Created = DateTime.Parse("2021-10-14T23:36:58.0340629Z"),
                                Group = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                IsExecutable = true,
                                LastModified = DateTime.Parse("2021-10-14T23:41:11.6798321Z"),
                                Owner = "S-1-12-1-1613650695-1152925323-3004084401-3676713700",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "S-1-5-11", "Modify, Synchronize" },
                                    { "S-1-5-18", "FullControl" },
                                    { "S-1-5-32-544", "FullControl" },
                                    { "S-1-5-32-545", "ReadAndExecute, Synchronize" }
                                },
                                SignatureStatus = new Objects.Signature(),
                                Size = 343480
                            },
                            CompareRunId = "2021-10-14T16:44:27.3260573-07:00",
                            Diffs = [
                                new Diff("ContentHash", 
                                    "7QGAoQeCLD64FeGxlSoeW5eHcACmyBrT1HIv+YOGVi2Of6c88DR6+Uk1O2zemHCGXAeJrtc+COi8yqHrnpX8Zg==",
                                    "Qpr6h4sgWi9HvNaKn1kWmznUifwU+8Uw6RjczVpkzx/LlGSyJgEhQ9pkMe6sX3wo9gwLmZicOIelU2b9NncLiw=="),
                                new Diff("LastModified", 
                                    "2021-10-13T03:05:24.3286411Z",
                                    "2021-10-14T23:41:11.6798321Z"),
                                new Diff("SignatureStatus"),
                                new Diff("Size", 726896, 343480)
                            ],
                            AnalysesHash = "yXvUiHy+rkKstAubfKrepSYhf7tGW6Fmpq72cvzjHu/IFkPu1P6FEstdy15fnGvxhAyIcIzdWFTILRTZ6wy0yA==",
                            Rules = [
                                new AsaRule("Unsigned binaries"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS
                                  ],
                                  Clauses = [
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "is_exe",
                                      Arguments = []
                                    },
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "SignatureStatus.IsAuthenticodeValid",
                                      Label = "valid_windows_signature",
                                      Arguments = []
                                    },
                                    new Clause(Operation.IsNull){
                                      Data = [],
                                      DictData = [],
                                      Field = "MacSignatureStatus",
                                      Label = "null_mac_signature",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when unsigned/incorrectly signed binaries are added.",
                                  Expression = "is_exe AND NOT valid_windows_signature AND null_mac_signature",
                                  Target = "FileSystemObject",
                                  Tags = [],
                                  Flag = ANALYSIS_RESULT_TYPE.WARNING
                                },
                                new AsaRule("Missing DEP"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.WINDOWS
                                  ],
                                  Clauses = [
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "EXE",
                                      Arguments = []
                                    },
                                    new Clause(Operation.Contains){
                                      Data = [
                                        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"
                                      ],
                                      DictData = [],
                                      Field = "Characteristics",
                                      Label = "DEP",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when executables are created without DEP.",
                                  Expression = "EXE AND NOT DEP",
                                  Target = "FileSystemObject",
                                  Flag = ANALYSIS_RESULT_TYPE.WARNING,
                                  Tags = []
                                },
                                new AsaRule("Missing ASLR"){
                                  ChangeTypes = [
                                    CHANGE_TYPE.CREATED,
                                    CHANGE_TYPE.MODIFIED
                                  ],
                                  Platforms = [
                                    PLATFORM.WINDOWS
                                  ],
                                  Clauses = [
                                    new Clause(Operation.IsTrue){
                                      Data = [],
                                      DictData = [],
                                      Field = "IsExecutable",
                                      Label = "EXE",
                                      Arguments = []
                                    },
                                    new Clause(Operation.Contains){
                                      Data = [
                                        "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                                        "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"
                                      ],
                                      DictData = [],
                                      Field = "Characteristics",
                                      Label = "ASLR",
                                      Arguments = []
                                    }
                                  ],
                                  Description = "Flag when executables are created without ASLR.",
                                  Expression = "EXE AND NOT ASLR",
                                  Target = "FileSystemObject",
                                  Flag = ANALYSIS_RESULT_TYPE.WARNING,
                                  Tags = []
                                }
                            ]
                        }
                    }
                }
            };
            
            AsaResults outputDictionary = new(metadata, output);
            
            var rulesJson = File.ReadAllText(@"TestData/ExportTests/TestGenerateSarifLog/rules.json");
            var rulesList = JsonConvert.DeserializeObject<IEnumerable<AsaRule>>(rulesJson, jsonSettings);

            var sarif = AttackSurfaceAnalyzerClient.GenerateSarifLog(outputDictionary, rulesList, true);

            Assert.AreEqual(2, sarif.Runs[0].Artifacts.Count);
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestAddExe.exe"));
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestModifyExe.exe"));
            Assert.AreEqual(6, sarif.Runs[0].Results.Count);
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing DEP: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing ASLR: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Unsigned binaries: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
//            Assert.IsFalse(sarif.Runs[0].Results.Any(r => r.Message.Text.Contains("TestAddText.txt")));
            Assert.AreEqual(41, sarif.Runs[0].Tool.Driver.Rules.Count);
            Assert.IsTrue(sarif.Runs[0].Tool.Driver.Rules.Any(r => r.FullDescription.Text == "Flag when privileged ports are opened."));

            // Test with allowing impliciting findings
            sarif = AttackSurfaceAnalyzerClient.GenerateSarifLog(outputDictionary, rulesList, false);
            Assert.AreEqual(3, sarif.Runs[0].Artifacts.Count);
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestAddText.txt"));
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestAddExe.exe"));
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestModifyExe.exe"));
            Assert.AreEqual(7, sarif.Runs[0].Results.Count);
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing DEP: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing ASLR: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Unsigned binaries: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text.Contains("TestAddText.txt")));
            Assert.AreEqual(41, sarif.Runs[0].Tool.Driver.Rules.Count);
            Assert.IsTrue(sarif.Runs[0].Tool.Driver.Rules.Any(r => r.FullDescription.Text == "Flag when privileged ports are opened."));
        }

        /// <summary>
        ///     Identities such as a process "PID:Name" or a registry path containing a drive
        ///     letter were previously emitted as relative SARIF URIs whose first path segment
        ///     contained a colon, which consumers (e.g. GitHub code scanning) reject. Ensure
        ///     such identities are disambiguated into valid URI references.
        /// </summary>
        [TestMethod]
        public void TestGenerateSarifLogDisambiguatesColonIdentities()
        {
            Dictionary<string, string> metadata = new()
            {
                { "compare-version", "2.4.10-alpha+5351e91d1c" },
                { "compare-os", "WINDOWS" },
                { "compare-osversion", "Microsoft Windows NT 10.0.19043.0" },
                { "analyses-hash", "yXvUiHy+rkKstAubfKrepSYhf7tGW6Fmpq72cvzjHu/IFkPu1P6FEstdy15fnGvxhAyIcIzdWFTILRTZ6wy0yA==" }
            };

            Dictionary<string, ConcurrentBag<CompareResult>> output = new()
            {
                {
                    "PROCESS_CREATED", new ConcurrentBag<CompareResult>()
                    {
                        new()
                        {
                            Analysis = ANALYSIS_RESULT_TYPE.WARNING,
                            Compare = new ProcessObject(10132, "svchost")
                        },
                        new()
                        {
                            Analysis = ANALYSIS_RESULT_TYPE.WARNING,
                            Compare = new RegistryObject(
                                "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\Local Settings\\MrtCache\\C:\\Windows\\resources.pri",
                                Microsoft.Win32.RegistryView.Registry64)
                        }
                    }
                }
            };

            AsaResults outputDictionary = new(metadata, output);

            var sarif = AttackSurfaceAnalyzerClient.GenerateSarifLog(outputDictionary, Array.Empty<AsaRule>(), false);

            Assert.AreEqual(2, sarif.Runs[0].Artifacts.Count);

            foreach (var artifact in sarif.Runs[0].Artifacts)
            {
                Assert.IsNotNull(artifact.Location.Uri);

                // Mirrors the consumer check: the path is split on '/' and the first path
                // segment must not contain a colon.
                var firstSegment = artifact.Location.Uri.OriginalString.Split('/')[0];
                Assert.IsFalse(firstSegment.Contains(':'),
                    $"First path segment of '{artifact.Location.Uri.OriginalString}' must not contain a colon.");
            }

            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Uri.OriginalString == "./10132:svchost"));
        }
    }
}