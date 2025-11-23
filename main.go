package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/ethereum/go-ethereum/accounts"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/planxnx/ethereum-wallet-generator/bip39"
	"github.com/planxnx/ethereum-wallet-generator/utils"
	"github.com/planxnx/ethereum-wallet-generator/wallets"
)

// ReadSeeds reads a file containing one mnemonic per line and returns as a slice.
func ReadSeeds(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var seeds []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			seeds = append(seeds, line)
		}
	}
	return seeds, scanner.Err()
}

func main() {
	// Flags
	filePath := flag.String("seeds", "", "file containing list of BIP39 mnemonics (one per line)")
	depth := flag.Int("depth", 1, "number of addresses to derive per seed/mnemonic (default 1, >=1)")
	dbPath := flag.String("db", "", "set sqlite output name eg. wallets.db (db file will create in /db)")
	strict := flag.Bool("strict", false, "strict contains mode")
	contain := flag.String("contains", "", "show only result that contained with the given letters (support for multiple characters)")
	prefix := flag.String("prefix", "", "show only result that prefix was matched")
	suffix := flag.String("suffix", "", "show only result that suffix was matched")
	regEx := flag.String("regex", "", "show only result that was matched with given regex (eg. ^0x99 or ^0x00)")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --seeds parameter required, pointing to a file containing mnemonics")
		os.Exit(1)
	}
	if *depth < 1 {
		*depth = 1
	}

	seeds, err := ReadSeeds(*filePath)
	if err != nil {
		log.Fatalf("Failed to open seeds file: %v", err)
	}
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "No seeds/mnemonics found in the file.")
		return
	}
	totalToGenerate := len(seeds) * (*depth)

	// Prepare DB if requested
	var gdb *gorm.DB
	if *dbPath != "" {
		db, err := gorm.Open(sqlite.Open("./db/"+*dbPath), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		if err != nil {
			log.Fatalf("Failed to open sqlite DB: %v", err)
		}
		// Auto migrate wallets.Wallet
		if err := db.AutoMigrate(&wallets.Wallet{}); err != nil {
			log.Fatalf("AutoMigrate failed: %v", err)
		}
		gdb = db
	}

	// Prepare address validator
	r := regexp.MustCompile(*regEx)
	containsList := strings.Split(*contain, ",")
	*prefix = utils.Add0xPrefix(*prefix)

	validateAddress := func(address string) bool {
		isValid := true
		// contains logic
		if len(containsList) > 0 && containsList[0] != "" {
			found := false
			for _, c := range containsList {
				if strings.Contains(address, c) {
					found = true
					break
				}
			}
			if *strict && !found {
				isValid = false
			}
			if !*strict && !found {
				isValid = false
			}
		}
		if *prefix != "" && !strings.HasPrefix(address, *prefix) {
			isValid = false
		}
		if *suffix != "" && !strings.HasSuffix(address, *suffix) {
			isValid = false
		}
		if *regEx != "" && !r.MatchString(address) {
			isValid = false
		}
		return isValid
	}

	// Base derivation path from wallets package (m/44'/60'/0'/0)
	basePath := wallets.DefaultBaseDerivationPath
	basePathStr := wallets.DefaultBaseDerivationPathString

	count := 0
	for si, seedOrMnemonic := range seeds {
		seedBytes := bip39.NewSeed(seedOrMnemonic, "")

		for i := 0; i < *depth; i++ {
			// build path base + index i
			path := make(accounts.DerivationPath, len(basePath)+1)
			copy(path, basePath)
			path[len(basePath)] = uint32(i)

			privKey, err := wallets.DeriveWallet(seedBytes, path)
			if err != nil {
				log.Printf("Seed line %d index %d: Failed to derive wallet: %v", si+1, i, err)
				count++
				if count%50 == 0 {
					fmt.Printf("\rProcessed %d/%d", count, totalToGenerate)
				}
				continue
			}

			w, err := wallets.NewFromPrivatekey(privKey)
			if err != nil {
				log.Printf("Seed line %d index %d: NewFromPrivatekey failed: %v", si+1, i, err)
				count++
				if count%50 == 0 {
					fmt.Printf("\rProcessed %d/%d", count, totalToGenerate)
				}
				continue
			}
			w.HDPath = fmt.Sprintf("%s/%d", basePathStr, i)

			if validateAddress(w.Address) {
				if gdb != nil {
					if err := gdb.Create(w).Error; err != nil {
						log.Printf("DB save failed for seed %d idx %d: %v", si+1, i, err)
					}
				} else {
					// print a compact representation when no DB configured
					fmt.Printf("MATCH: seed_line=%d idx=%d addr=%s pk=%s hdpath=%s\n", si+1, i, w.Address, w.PrivateKey, w.HDPath)
				}
			}

			count++
			if count%50 == 0 {
				fmt.Printf("\rProcessed %d/%d", count, totalToGenerate)
			}
		}
	}

	// final progress newline
	fmt.Printf("\rProcessed %d/%d\n", count, totalToGenerate)
}
