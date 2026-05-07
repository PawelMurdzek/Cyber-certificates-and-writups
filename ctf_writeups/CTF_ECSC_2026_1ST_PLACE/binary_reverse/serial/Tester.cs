using System;
using System.Reflection;

class Tester
{
    static void Main(string[] args)
    {
        var asm = Assembly.LoadFrom(@"C:\projekty\cyber.mil\binary_reverse\serial\CrackMe.exe");
        var formType = asm.GetType("CrackMe.Form1");
        var inst = Activator.CreateInstance(formType);
        var miCN = formType.GetMethod("ComputeName", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var miSS = formType.GetMethod("ShiftSerial", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var miCS = formType.GetMethod("ComputeSerial", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var miCSNS = formType.GetMethod("ComputeSerialNumberSum", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        string name = "LABORATORIUM";
        int nameVal = (int)miCN.Invoke(inst, new object[] { name });
        Console.WriteLine("ComputeName('LABORATORIUM') = " + nameVal);

        string[] candidates = { "90817146", "90817263", "90818127", "90818244", "90818541", "90818730" };
        foreach (var cand in candidates)
        {
            int sumOrig = (int)miCSNS.Invoke(inst, new object[] { cand });
            string shifted = (string)miSS.Invoke(inst, new object[] { cand });
            int parsed = int.Parse(shifted);
            int divResult = parsed / 1867;
            int serial = (int)miCS.Invoke(inst, new object[] { shifted });
            bool ok = (cand.Length == 8) && (sumOrig == 36) && (divResult == 53480) && (nameVal == serial);
            Console.WriteLine(string.Format("  {0}: sumOrig={1}, shifted='{2}', parsed={3}, /1867={4}, computeSerial={5}, MATCH={6}",
                cand, sumOrig, shifted, parsed, divResult, serial, ok));
        }
    }
}
