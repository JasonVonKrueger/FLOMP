# FLOMP

FLOMP or Flagged Compromised is a simple (depending on who you are) node app that returns true or false if an account has been flagged as compromised.
If true, a reason will also be provided.

The endpoint URI is simply `/isflagged/<username>`.

The result will be something like:

```json
{
  "isflagged":true,
  "flaggedreason":"We believe your account may have been compromised due to a high volume of e-mail being sent from it. Please reset your password by clicking the Forgot Password link on the right. Visit the HUB to verify your computer is not infected."
}
```
or 
```json
{
  "isflagged":false,
  "flaggedreason":null
}
```






