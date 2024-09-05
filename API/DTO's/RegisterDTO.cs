using System;
using System.ComponentModel.DataAnnotations;

namespace API.DTO_s;

public class RegisterDTO
{

[Required]
public required string Username { get; set; }
    
[Required]
public required string Password { get; set; }
}
