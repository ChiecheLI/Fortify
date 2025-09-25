;; Fortify - Smart Contract Security Scanner
;; A decentralized security scanning platform for Clarity smart contracts

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_SCANNER (err u103))

;; Data Variables
(define-data-var scan-counter uint u0)
(define-data-var platform-fee uint u1000000) ;; 1 STX in microSTX

;; Data Maps
(define-map scans
    { scan-id: uint }
    {
        contract-address: principal,
        scanner: principal,
        timestamp: uint,
        severity-score: uint,
        vulnerabilities-found: uint,
        scan-result-hash: (string-ascii 64),
        is-verified: bool
    }
)

(define-map scanners
    { scanner-address: principal }
    {
        reputation-score: uint,
        total-scans: uint,
        verified-scans: uint,
        is-active: bool
    }
)

(define-map contract-scans
    { contract-address: principal }
    {
        latest-scan-id: uint,
        scan-count: uint,
        best-score: uint
    }
)

;; Authorization map for verified scanners
(define-map authorized-scanners principal bool)

;; Public Functions

;; Register a new security scanner
(define-public (register-scanner)
    (let ((caller tx-sender))
        (asserts! (is-none (map-get? scanners { scanner-address: caller })) ERR_ALREADY_EXISTS)
        (map-set scanners 
            { scanner-address: caller }
            {
                reputation-score: u0,
                total-scans: u0,
                verified-scans: u0,
                is-active: true
            }
        )
        (ok true)
    )
)

;; Submit a security scan result
(define-public (submit-scan (contract-address principal) (severity-score uint) (vulnerabilities-found uint) (scan-result-hash (string-ascii 64)))
    (let (
        (caller tx-sender)
        (new-scan-id (+ (var-get scan-counter) u1))
        (scanner-data (unwrap! (map-get? scanners { scanner-address: caller }) ERR_INVALID_SCANNER))
    )
        ;; Ensure scanner is registered and active
        (asserts! (get is-active scanner-data) ERR_INVALID_SCANNER)
        
        ;; Pay platform fee
        (try! (stx-transfer? (var-get platform-fee) caller CONTRACT_OWNER))
        
        ;; Create scan record
        (map-set scans
            { scan-id: new-scan-id }
            {
                contract-address: contract-address,
                scanner: caller,
                timestamp: stacks-block-height,
                severity-score: severity-score,
                vulnerabilities-found: vulnerabilities-found,
                scan-result-hash: scan-result-hash,
                is-verified: false
            }
        )
        
        ;; Update scanner stats
        (map-set scanners
            { scanner-address: caller }
            (merge scanner-data { total-scans: (+ (get total-scans scanner-data) u1) })
        )
        
        ;; Update contract scan tracking
        (let ((contract-data (default-to 
                { latest-scan-id: u0, scan-count: u0, best-score: u100 }
                (map-get? contract-scans { contract-address: contract-address })
            )))
            (map-set contract-scans
                { contract-address: contract-address }
                {
                    latest-scan-id: new-scan-id,
                    scan-count: (+ (get scan-count contract-data) u1),
                    best-score: (if (< severity-score (get best-score contract-data)) 
                                   severity-score 
                                   (get best-score contract-data))
                }
            )
        )
        
        ;; Update scan counter
        (var-set scan-counter new-scan-id)
        
        (ok new-scan-id)
    )
)

;; Verify a scan (only authorized scanners can verify others' scans)
(define-public (verify-scan (scan-id uint))
    (let (
        (caller tx-sender)
        (scan-data (unwrap! (map-get? scans { scan-id: scan-id }) ERR_NOT_FOUND))
        (original-scanner (get scanner scan-data))
    )
        ;; Ensure caller is authorized and not verifying their own scan
        (asserts! (default-to false (map-get? authorized-scanners caller)) ERR_UNAUTHORIZED)
        (asserts! (not (is-eq caller original-scanner)) ERR_UNAUTHORIZED)
        
        ;; Mark scan as verified
        (map-set scans
            { scan-id: scan-id }
            (merge scan-data { is-verified: true })
        )
        
        ;; Update original scanner's reputation
        (let ((scanner-data (unwrap! (map-get? scanners { scanner-address: original-scanner }) ERR_NOT_FOUND)))
            (map-set scanners
                { scanner-address: original-scanner }
                (merge scanner-data { 
                    verified-scans: (+ (get verified-scans scanner-data) u1),
                    reputation-score: (+ (get reputation-score scanner-data) u10)
                })
            )
        )
        
        (ok true)
    )
)

;; Admin function to authorize scanners
(define-public (authorize-scanner (scanner principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
        (map-set authorized-scanners scanner true)
        (ok true)
    )
)

;; Admin function to set platform fee
(define-public (set-platform-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
        (var-set platform-fee new-fee)
        (ok true)
    )
)

;; Read-only Functions

;; Get scan details
(define-read-only (get-scan (scan-id uint))
    (map-get? scans { scan-id: scan-id })
)

;; Get scanner details
(define-read-only (get-scanner (scanner-address principal))
    (map-get? scanners { scanner-address: scanner-address })
)

;; Get contract scan summary
(define-read-only (get-contract-summary (contract-address principal))
    (map-get? contract-scans { contract-address: contract-address })
)

;; Get latest scan for a contract
(define-read-only (get-latest-scan (contract-address principal))
    (let ((contract-data (map-get? contract-scans { contract-address: contract-address })))
        (match contract-data
            summary (map-get? scans { scan-id: (get latest-scan-id summary) })
            none
        )
    )
)

;; Get current scan counter
(define-read-only (get-scan-counter)
    (var-get scan-counter)
)

;; Get platform fee
(define-read-only (get-platform-fee)
    (var-get platform-fee)
)

;; Check if scanner is authorized
(define-read-only (is-authorized-scanner (scanner principal))
    (default-to false (map-get? authorized-scanners scanner))
)