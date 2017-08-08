using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

/*  Background: 
 *  
 *  The US Department of Defense produces a collection of security hardening guides for various products (OS, web servers, network appliances, etc) 
 *  called Security Technical Implementation Guidelines (STIGs), in concert with NSA, CERT, software vendors (i.e. Microsoft), and other security organizations.  
 *  
 *  For example, here's the web server section of that collection:
 *  http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
 *  They also have tools used to assist with scanning for STIG compliance -- SCAP benchmark scanner -- and documentation of compliance status -- STIG Viewer, 
 *  which creates checklists based on STIG content for easy review by cybersecurity inspection teams.  An individual vulnerability check might be setting a 
 *  Windows registry value to disable legacy SSL support, ensuring services/applications are being run with minimum required permissions, strong encryption 
 *  is being used for data in transit / data at rest, and so on.
 */
 
/*
 *  One of the issues we ran into during our last major security review was that our inspection team need us to identify which findings had been manually reviewed 
 *  & closed and which ones had been marked as closed by the SCAP scanning tool, and there isn't any built-in way to do so.  This tool extracts the output from 
 *  the SCAP scanner (XCCDF-formatted XML data) and updates an existing STIG Viewer checklist with the scan results, adding comments to indicate which findings were 
 *  closed by SCAP (i.e. "MARKED AS 'OPEN' BY SCAP SCAN").
 */


// SCAPComments
// Used to update a STIG Viewer Checklist based on the XCCDF results file from a SCAP vulnerability scan.
// Vulnerability status (Open, Not a Finding, Not Appliciable) will be updated and a comment will be added based on the 
// scan results (i.e. "[Date] MARKED AS OPEN").

namespace SCAPComments
{
    class Transfer_SCAPResults
    {
        static Hashtable _VulnsList = new Hashtable();
        static XmlDocument _SCAPResults;
        static XmlDocument _CheckList;
        static StringBuilder _LogBuffer = new StringBuilder();

        static void Main(string[] args)
        {
            if (args.Length == 2 && CheckFiles(args))
            {
                Load_SCAPResults();
                UpdateComments(args[1]);
            }
            else
            {
                Console.WriteLine("Adds comments to a STIG Viewer _CheckList file based on supplied SCAP scan results (XCCDF format).");
                Console.WriteLine("SCAPTransfer.exe [in] [out] ");
                Console.WriteLine("-[in]\t Input SCAP reults filename (XCCDF formatted-XML file)");
                Console.WriteLine("-[out]\t Target .ckl filename.");
                Console.WriteLine("Ex:\tSCAPTransfer.exe NI5444-COI_IE11_V1R20.XML NI5444-COI_IE11.ckl");
            }
        }

        // Load the XmlDocuments or return false if either file fails to load.
        private static Boolean CheckFiles(String[] args)
        {
            bool filesLoaded = true;
            try
            {
                _LogBuffer.AppendLine("Loading SCAP results file.");
                Console.WriteLine("Loading SCAP results file.");
                _SCAPResults = new XmlDocument();
                _SCAPResults.Load(args[0]);
            }
            catch (Exception ex)
            {
                filesLoaded = false;
                Console.WriteLine("An error occurred when attempting to load SCAP results file: {0}\nDetails{1}", args[0], ex.ToString());
            }
            try
            {
                Console.WriteLine("Loading target checklist file.");
                _LogBuffer.AppendLine("Loading target checklist file.");
                _CheckList = new XmlDocument();
                _CheckList.Load(args[1]);
            }
            catch (Exception ex)
            {
                filesLoaded = false;
                Console.WriteLine("An error occurred when attempting to load target checklist file: {0}\nDetails{1}", args[1], ex.ToString());
            }
            return filesLoaded;
        }

        //  Build a Hashtable of RuleID keys and pass/fail values
        private static void Load_SCAPResults()
        {
            XmlNode root = _SCAPResults.DocumentElement;
            XmlNamespaceManager xnm = new XmlNamespaceManager(_SCAPResults.NameTable);
            xnm.AddNamespace("cdf", "http://checklists.nist.gov/xccdf/1.1");

            XmlNodeList allResults = root.SelectNodes("cdf:TestResult/cdf:rule-result", xnm);

            Console.WriteLine("Found " + allResults.Count + " entries in SCAP results file."); 
            _LogBuffer.AppendLine("Found " + allResults.Count + " entries in SCAP results file.");
            foreach (XmlNode x in allResults)
            {
                String ruleID = x.Attributes["idref"].Value;
                String result = x.SelectSingleNode("cdf:result", xnm).InnerText;
                _VulnsList[ruleID] = result;
            }
        }

        // Search the .CKL file by RuleID and set the appropriate comment for pass/fail
        private static void UpdateComments(String targetFilename)
        {
            XmlNode root = _CheckList.DocumentElement;

            foreach (String key in _VulnsList.Keys)
            {

                XmlNode vuln = root.SelectSingleNode(String.Format("/CHECKLIST/STIGS/iSTIG/VULN[STIG_DATA[ATTRIBUTE_DATA[text()='{0}']]]", key));
                if (vuln == null)
                {
                    _LogBuffer.AppendLine(String.Format("VulID {0} not found in new checklist.  Skipping...", key));
                }
                else
                {
                    _LogBuffer.Append(key + " -- Original: '" + vuln.SelectSingleNode("STATUS").InnerText + "'");
                    if (_VulnsList[key].ToString().Equals("pass", StringComparison.CurrentCultureIgnoreCase))
                    {
                        vuln.SelectSingleNode("STATUS").InnerText = "NotAFinding";
                        vuln.SelectSingleNode("COMMENTS").InnerText += "\n" + DateTime.Now.ToShortDateString() + ":  MARKED AS 'NOT A FINDING' BY SCAP SCAN\n";
                    }
                    else
                    {
                        vuln.SelectSingleNode("STATUS").InnerText = "Open";
                        vuln.SelectSingleNode("COMMENTS").InnerText += "\n" + DateTime.Now.ToShortDateString() + ":  MARKED AS 'OPEN' BY SCAP SCAN\n";
                    }

                    _LogBuffer.Append("\tAfter:  '" + vuln.SelectSingleNode("STATUS").InnerText + "'");
                    _LogBuffer.AppendLine();
                }

            }
            File.WriteAllText(targetFilename + ".log", _LogBuffer.ToString());
            _CheckList.Save(targetFilename);
        }
    }
}
