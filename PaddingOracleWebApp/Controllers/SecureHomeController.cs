using PaddingOracleWebApp.Helpers;
using System;
using System.Security.Cryptography;
using System.Web.Mvc;

namespace PaddingOracleWebApp.Controllers
{
    public class SecureHomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult Encrypt()
        {
            return View("Index");
        }

        [HttpPost]
        public ActionResult Encrypt(string plainText)
        {
            ViewBag.PlainText = plainText;
            byte[] encryptedBytes = AESCrypto.AES_EncryptString(plainText);
            string encryptedHexString = CryptoHelper.ConvertByteArrayToHexString(encryptedBytes);

            ViewBag.EncryptedHexString = encryptedHexString + "&HMacToken=" + GenerateHMac(encryptedHexString);
            return View("Index");
        }
        public static string GenerateHMac(string cipherText)
        {
            string HMacToken = TamperProofQueryString.GetTamperProofToken(cipherText);
            return HMacToken;
        }

        public ActionResult Decrypt(string secret, string HMacToken)
        {
            string msg = string.Empty;
            bool isValidQueryString = TamperProofQueryString.ValidateQueryString(secret, HMacToken, out msg);
            if (isValidQueryString)
            {
                string plainText = "The Magic Words are Squeamish Ossifrage";
                string response = "";
                if (string.IsNullOrEmpty(secret))
                {
                    response = "No secret? Sorry, bad request!";
                    ViewBag.DecryptedText = response;
                    HttpContext.Response.StatusCode = 400;
                    return View();
                }
                try
                {
                    byte[] encryptedBytes = CryptoHelper.ConvertHexStringToByteArray(secret);
                    response = AESCrypto.AES_DecryptToString(encryptedBytes);

                    if (plainText.Equals(response, StringComparison.OrdinalIgnoreCase))
                    {
                        //Valid padding and valid plain text
                        HttpContext.Response.StatusCode = 200;
                    }
                    else
                    {
                        //Valid padding, but incorrect format")
                        HttpContext.Response.StatusCode = 404;
                    }
                }
                catch (CryptographicException cex)
                {
                    //Invalid padding (Exception message: "Padding is invalid and cannot be removed.")
                    HttpContext.Response.StatusCode = 403;
                    response = cex.Message;
                }
                ViewBag.DecryptedText = response;
                return View();
            }
            else
            {
                ViewBag.ErrorMessage = msg;
                return View("AccessDenied");
            }
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }
    }
}