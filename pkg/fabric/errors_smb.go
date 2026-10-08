package fabric

import (
	"errors"

	smb2 "github.com/hirochachacha/go-smb2"
)

// smbCredentialStatuses are the NTSTATUS values (MS-ERREF 2.3.1) with which an
// SMB server refuses a session setup because of the credentials or the
// account: the login must never be repeated with the same credentials (a lockout
// threshold counts failed logons). File-level statuses such as
// STATUS_ACCESS_DENIED (0xC0000022) or STATUS_OBJECT_NAME_NOT_FOUND are NOT in
// the set: they answer about one file.
var smbCredentialStatuses = map[uint32]bool{
	0xC000006A: true, // STATUS_WRONG_PASSWORD
	0xC0000064: true, // STATUS_NO_SUCH_USER
	0xC000006D: true, // STATUS_LOGON_FAILURE
	0xC000006E: true, // STATUS_ACCOUNT_RESTRICTION
	0xC000006F: true, // STATUS_INVALID_LOGON_HOURS
	0xC0000070: true, // STATUS_INVALID_WORKSTATION
	0xC0000071: true, // STATUS_PASSWORD_EXPIRED
	0xC0000072: true, // STATUS_ACCOUNT_DISABLED
	0xC000015B: true, // STATUS_LOGON_TYPE_NOT_GRANTED
	0xC0000193: true, // STATUS_ACCOUNT_EXPIRED
	0xC0000224: true, // STATUS_PASSWORD_MUST_CHANGE
	0xC0000234: true, // STATUS_ACCOUNT_LOCKED_OUT
}

// isSMBCredentialFailure reports whether err carries the go-smb2 response error
// of a refused logon. go-smb2 prints such an error as "response error: " plus
// the MS-ERREF description ("The attempted logon is invalid. ..."), which holds
// none of the text markers, so only the typed code identifies it.
func isSMBCredentialFailure(err error) bool {
	var re *smb2.ResponseError
	return errors.As(err, &re) && smbCredentialStatuses[re.Code]
}
