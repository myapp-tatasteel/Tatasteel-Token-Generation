using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace FunctionApp6
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];
            string Api_key = req.Query["api-key"];
            string Secret_key = req.Query["Secret"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            string key = Secret_key;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var secToken = new JwtSecurityToken(signingCredentials: credentials, issuer: "SuperApp_Program", audience: "TSL-APIGEE-GenerateJWT-SuperApp",
            claims: new[]  { new System.Security.Claims.Claim("apikey", Api_key),
            new System.Security.Claims.Claim("appName", "SuperApp")
           },
            notBefore: DateTime.UtcNow.AddSeconds(-100),
            expires: DateTime.UtcNow.AddSeconds(200));
            var handler = new JwtSecurityTokenHandler();
            var tkn = handler.WriteToken(secToken);

            string decryptref = AESEncryption.DecodeAndDecrypt("JL0kv7IZ61/uCoBkEDzzYA==");



            string encryptedref3 = AESEncryption.EncryptAndEncode(name);

            var myData = new
            {
                jwttoken = tkn,
                pno = encryptedref3
            };

            return new OkObjectResult(myData);

        //https://tokengeneration20220822115328.azurewebsites.net?name=157092&api-key=RGkt9jU7cyUQwFkS9XakdAyA8XD7alj9&Secret=41b5c575-078d-4cac-8a58-990e66fa2a50
            //http://localhost:7071/api/Function1?name=157092&api-key=RGkt9jU7cyUQwFkS9XakdAyA8XD7alj9&Secret=41b5c575-078d-4cac-8a58-990e66fa2a50
        }
    }
}
