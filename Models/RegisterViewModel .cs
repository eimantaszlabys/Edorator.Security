using System;
using System.ComponentModel.DataAnnotations;

namespace Edorator.Security.Models
{
    public class RegisterViewModel 
    {
        public string Email { get; set; }

        public string Password { get; set; }
    }
}