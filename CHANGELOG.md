# Change Log
## 2.4.0

   * Fixed: issue in the 'Authorize' button don't show on Safari Mobile.
   * Upgrade to FIDO2 0.9.2, to fix issue with Windows 11.
   * Fixed: Minor Typos.


## 2.3.0
   * Fixed: A missing import Thanks @AndreasDickow
   * Fixed: `MFA.html` now call `{{block.super}}` for head and content blocks, thanks @mnelson4
   * Added: #55 introduced `mfa_base.html` which will be extended by `MFA.html` for better styling 

## 2.2.0
   * Added: MFA_REDIRECT_AFTER_REGISTRATION settings parameter
   * Fixed: Deprecation error for NULBooleanField

## 2.1.2
  * Fixed: Getting timestamp on Python 3.7 as ("%s") is raising an exception
  * Upgraded to FIDO 0.9.1


## 2.1.1
  * Fixed: FIDO2 version in requirements.txt file.
  
## 2.1.0
   * Added Support for Touch ID for Mac OSx and iOS 14 on Safari

## 2.0.5
  * Fixed issue in __version__

## 2.0.4
   * Fixed: Closes #30


## 2.0.3
  * Fixed: __version__ to show correct version

## 2.0.2
  * Added: A missing migration 
    thnks to @swainn

## 2.0.1
  * Fixed: issue in migration between Postgres and SQLite
    thnks to @swainn and @willingham 

## 2.0
  * Dropped support to djangp-1.8 and Python 2.7
  * Added: never-cache decorator
  * Fixes to Make Email Method More Robust 
  * Addresses several structure and style issues with TOTP and Email dialogs
  * Updated to fido2 0.8.1
    
Thanks to @swainn

## v1.9.1
   * Fixed: is_authenticated #13
   * Fixed: is_anonymous #6
    
    thanks to @d3cline,  

## v1.7
  * Better Error Management
  * Better Token recheck
## v 1.6.0
  * Fixed some issues for django>= 2.0
  * Added example app.

## v.1.5.0
  * Added id the key used to validate to the session dictionary as 'id'
## v1.4.0
  * Updated to FIDO == 0.7

## v1.3.0
  * Updated to FIDO2 == 0.6
  * Windows Hello is now supported.

## v1.2.0
 * Added:  MFA_HIDE_DISABLE setting option to disable users from deactivating their keys.
