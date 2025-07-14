using Microsoft.Extensions.FileProviders;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.Json;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Text;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseStaticFiles(new StaticFileOptions{
    FileProvider = new PhysicalFileProvider("/var/www/project"),
    RequestPath = ""
});


// Handle the access to the main page of website 
app.MapGet("/", (HttpContext clientCert) => {
    bool testProof = false;
    X509Certificate2? cert = null;
    
    // Get the header sent by Apache's Proxy
    try{
        var x509cert = clientCert.Request.Headers["X-SSL-Client-Cert"].ToString();
        if(string.IsNullOrEmpty(x509cert)){
            Console.WriteLine("Error getting the certificate");
            return Results.Ok(testProof);
        }


        // Remove headers and undesired characters from the certificate
        x509cert = x509cert 
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace(" ","")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        // Conversion of base64 certificate  
        byte[] x509B = Convert.FromBase64String(x509cert);
        cert = new X509Certificate2(x509B);

    }catch(FormatException e){
        Console.WriteLine($"Certificate format error: {e}");
        return Results.File("/var/www/project/accessDenied.html", "text/html");
    }catch(Exception e){
        Console.WriteLine($"Error while parsing: {e}");
        return Results.File("/var/www/project/accessDenied.html", "text/html");
    }

    // Check the number of extensions [debug only]
    Console.WriteLine($"Extensions count: {cert.Extensions.Count}");

    if(cert.Extensions.Count == 0){
        return Results.File("/var/www/project/accessDenied.html", "text/html");
    }
    
    // Get the desired extension and if present in certificate
    foreach(X509Extension ext in cert.Extensions){
       if(ext.Oid.Value == "1.2.3.4.5.6.7.8"){
            try{
                // Parsing from Asn encoded to String
                var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);

                // Read the value from extension field
                byte[] octetString = reader.ReadOctetString();
                string b64Info = Encoding.ASCII.GetString(octetString);
                
                // Decode de base64 extension
                byte[] decodedB = Convert.FromBase64String(b64Info);
                
                testProof = handleMethod.verifyAge(decodedB, decodedB.Length);
                Console.WriteLine($"Proof Verified? {testProof}"); 
                Console.Out.Flush(); 

            }catch(AsnContentException e){
                Console.WriteLine($"Erro on ASN1 parsing: {e}");
                return Results.File("/var/www/project/accessDenied.html", "text/html");;
            }catch(FormatException e){
                Console.WriteLine($"Error on base64 decoding: {e}");
                return Results.File("/var/www/project/accessDenied.html", "text/html");
            }catch(Exception e){
                Console.WriteLine($"Error on age verification: {e}");
                return Results.File("/var/www/project/accessDenied.html", "text/html");
            }
       }
    }
    return Results.File(testProof ? "/var/www/project/index.html" : "/var/www/project/accessDenied.html" , "text/html"); 
}); 

// Handles the creation of a age proof
app.MapPost("/generate_proof", async(HttpContext context) =>{


try{

    // Get the value sent by the html form
    var form = await context.Request.ReadFormAsync();
    int age = int.Parse(form["ageInput"]);

    var proofFile = "/home/rafael/project/zkp_data.b64";

    try{

        bool val = handleMethod.generateProof(age);

        if(val){
            Console.WriteLine("Proof not generated");
        }
    }catch(Exception e){
        return Results.Content($"<script>alert('Proof not generated'); window.location.href = 'accessDenied.html'; </script>", "text/html");
    }
    var convertFile = new ProcessStartInfo{
            FileName = "/home/rafael/scripts/convertProof.sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
    };

    var process = Process.Start(convertFile);
    string output = await process.StandardOutput.ReadToEndAsync();
    string error = await process.StandardError.ReadToEndAsync();
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        Console.WriteLine($"Script failed: {error}");
        return Results.Content($"<script>alert('Error while converting file.'); window.location.href = 'accessDenied.html' ;</script>", "text/html");
    }

    var stream = File.OpenRead(proofFile);

    var cleanFiles = new ProcessStartInfo{
            FileName = "/home/rafael/scripts/cleanProof.sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
    };

    process = Process.Start(cleanFiles);
    output = await process.StandardOutput.ReadToEndAsync();
    error = await process.StandardError.ReadToEndAsync();
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        Console.WriteLine("Cleaning the proof files failed.");

    }

    return Results.File(stream, "text/plain", "age_proof.b64");
}catch (Exception ex){
    Console.WriteLine($"Error on endpoint: {ex}");
    return Results.Content($"<script>alert('Error generating the proof'); window.location.href = 'accessDenied.html' ; </script>", "text/html");

}
});

app.MapPost("/create_certificate", async (HttpRequest req) =>
{
    try{
        var form = await req.ReadFormAsync();

        string cn = form["cn"];
        string o = form["o"];
        string ou = form["ou"];
        string l = form["l"];
        string st = form["st"];
        string c = form["c"];
        string email = form["email"];

        var file = form.Files.GetFile("b64file");
        if (file == null || file.Length == 0 || !Path.GetExtension(file.FileName).Equals(".b64")){
            //return Results.BadRequest("No .b64 file uploaded");
            return Results.Content($"<script>alert('Invalid File Type'); window.location.href = 'accessDenied.html' ;</script>", "text/html");
        }

        var tempPath = Path.GetTempFileName();
        using (var stream = new FileStream(tempPath, FileMode.Create)){
            await file.CopyToAsync(stream);
        }

        // Defines the args for openssl command that requests the cert
        string args = $"\"{cn}\" \"{o}\" \"{ou}\" \"{l}\" \"{st}\" \"{c}\" \"{email}\" \"{tempPath}\"";

        var generateCert = new ProcessStartInfo
        {
            FileName = "/home/rafael/scripts/script_generate_cert.sh",
            Arguments = $"script_generate_cert.sh {args}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var process = Process.Start(generateCert);
        string output = await process.StandardOutput.ReadToEndAsync();
        string error = await process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        // Clean temp file 
        System.IO.File.Delete(tempPath);

        if (process.ExitCode != 0)
        {
            Console.WriteLine($"Script failed: {error}");
            return Results.Content($"<script>alert('Error while creating certification'); window.location.href = 'accessDenied.html' ;</script>", "text/html");
        }

        string certFilePath = "/home/rafael/site/certificate.p12"; 
	
	    var stream1 = new FileStream(certFilePath, FileMode.Open, FileAccess.Read);
	    var contentType = "application/x-pem-file"; 
	    var fileName = Path.GetFileName(certFilePath);

        var cleanProcess = new ProcessStartInfo{
            FileName = "/home/rafael/scripts/clean.sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true

        };

        var process1 = Process.Start(cleanProcess);
        string output1 = await process1.StandardOutput.ReadToEndAsync();
        string error1 = await process1.StandardError.ReadToEndAsync();
        process1.WaitForExit();

        if (process1.ExitCode != 0)
        {
            Console.WriteLine($"Script failed: {error}");
            return Results.Content($"<script>alert('Error while cleaning the system.'); window.location.href = 'accessDenied.html' ;</script>", "text/html");
        }

	    return Results.File(stream1, contentType, fileName);    
	}catch (Exception ex){
        Console.WriteLine($"Error on endpoint: {ex}");
        //return Results.StatusCode(500);
        return Results.Content($"<script>alert('Error generating Certificate'); window.location.href = 'accessDenied.html' ;</script>", "text/html");
    }
});

app.Run();
