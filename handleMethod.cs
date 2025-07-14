using System;
using System.Runtime.InteropServices;

class handleMethod{
    
    [DllImport("libverifyAge.so", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool verifyAge(byte[] info, int tam);

    [DllImport("libgenerateProof.so", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool generateProof(int age);
}
