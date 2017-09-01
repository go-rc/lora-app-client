package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	context "golang.org/x/net/context"

	pb "github.com/brocaar/lora-app-server/api"
	"github.com/brocaar/lorawan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type jsonPayload struct {
	Mhdr struct {
		Mtype string `json:"mType"`
		Major string `json:"major"`
	} `json:"mhdr"`
	MacPayload struct {
		Fhdr struct {
			Devaddr string `json:"devAddr"`
			Fcnt    uint32 `json:"fCnt"`
		} `json:"fhdr"`
		FrmPayload []struct {
			Bytes string `json:"bytes"`
		} `json:"frmPayload"`
	} `json:"macPayload"`
	Mic string `json:"mic"`
}

var (
	crt = "cert.crt"
	key = "cert.key"
)

var usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nYour certificates could be generated with the following commands:\n\n")
	fmt.Fprintf(os.Stderr, "\topenssl genrsa -out cert.key 2048\n")
	fmt.Fprintf(os.Stderr, "\topenssl ecparam -genkey -name secp384r1 -out cert.key\n")
	fmt.Fprintf(os.Stderr, "\topenssl req -new -x509 -sha256 -key cert.key -out cert.crt -days 3650\n")
}

/*
	Type and funcs to fulfill credentials.PerRPCCredentials interface
*/
type authKey struct {
	key string
}

func (a authKey) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": a.key,
	}, nil
}
func (a authKey) RequireTransportSecurity() bool {
	return true
}

func isUplink(mtype string) bool {
	switch mtype {
	case "JoinRequest", "UnconfirmedDataUp", "ConfirmedDataUp":
		return true
	default:
		return false
	}
}

func main() {
	flag.Usage = usage
	backend := flag.String("b", "your-lora-app-server:443", "address of the lora-app-server backend")
	username := flag.String("u", "admin", "login username")
	password := flag.String("p", "", "login password")
	crt := flag.String("c", crt, "TLS certificate file")
	key := flag.String("k", key, "TLS certificate key")
	flag.Parse()

	ctx := context.Background()

	if *backend == "" {
		log.Printf("ERROR: missing backend\n\n")
		flag.PrintDefaults()
		return
	}

	if *username == "" {
		log.Printf("ERROR: missing username\n\n")
		flag.PrintDefaults()
		return
	}

	if *password == "" {
		log.Printf("ERROR: missing password\n\n")
		flag.PrintDefaults()
		return
	}

	creds, err := credentials.NewServerTLSFromFile(*crt, *key)
	if err != nil {
		log.Fatalf("could not load TLS certificate or key: %s", err)
	}

	conn, err := grpc.Dial(*backend, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("could not connect to %s: %v", *backend, err)
	}
	defer conn.Close()

	ic := pb.NewInternalClient(conn)
	loginRequest := pb.LoginRequest{Username: *username, Password: *password}
	resp, err := ic.Login(ctx, &loginRequest)
	if err != nil {
		log.Fatalf("could not login %v", err)
	}

	// Connect again, this time with the authorization JWT
	conn2, err := grpc.Dial(*backend,
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(authKey{resp.Jwt}))
	if err != nil {
		log.Fatalf("could not connect to %s: %v", *backend, err)
	}
	defer conn2.Close()

	ic = pb.NewInternalClient(conn2)
	pr := new(pb.ProfileRequest)
	profile, err := ic.Profile(ctx, pr)
	if err != nil {
		log.Fatalf("could not retrieve profile %v", err)
	}

	nc := pb.NewNodeClient(conn2)

	fmt.Printf("User ID:\t%d\n", profile.User.Id)
	fmt.Printf("User Name:\t%s\n", profile.User.Username)

	var appSKey lorawan.AES128Key
	var devAddr lorawan.DevAddr

	for _, app := range profile.Applications {
		fmt.Printf("\nApplication \"%s\"\n", app.ApplicationName)
		nbaid := pb.ListNodeByApplicationIDRequest{ApplicationID: app.ApplicationID, Limit: 10, Offset: 0}
		nodes, err := nc.ListByApplicationID(ctx, &nbaid)
		if err != nil {
			log.Fatalf("could not retrieve application nodes %v\n", err)
		}
		fmt.Printf("Nodes: (%d)\n", nodes.TotalCount)

		for _, node := range nodes.Result {
			fmt.Printf("\n\tDevEUI:\t%s\n", node.DevEUI)
			fmt.Printf("\tDescription:\t%s\n", node.Description)
			flr := pb.GetFrameLogsRequest{DevEUI: node.DevEUI, Limit: 0, Offset: 0}
			frmlogs, err := nc.GetFrameLogs(ctx, &flr)
			if err != nil {
				log.Fatalf("could not retrieve node frame count %v\n", err)
			}
			fmt.Printf("\tFrame Count:\t%d\n", frmlogs.TotalCount)

			nar := pb.GetNodeActivationRequest{DevEUI: node.DevEUI}
			activation, err := nc.GetActivation(ctx, &nar)

			if err != nil {
				log.Fatalf("could not retrieve node activation info %v\n", err)
			}

			if frmlogs.TotalCount > 0 {
				flr = pb.GetFrameLogsRequest{DevEUI: node.DevEUI, Limit: 1, Offset: 0}
				frmlogs, err := nc.GetFrameLogs(ctx, &flr)
				if err != nil {
					log.Fatalf("could not retrieve last node frame %v\n", err)
				}
				dec := json.NewDecoder(strings.NewReader(frmlogs.Result[0].PhyPayloadJSON))
				var payload jsonPayload
				err = dec.Decode(&payload)
				if err != nil {
					log.Fatalf("could not retrieve last node frame %v\n", err)
				} else {
					fmt.Print("\t=== Last Message ===\n")
					fmt.Printf("\tType:\t\t%s\n", payload.Mhdr.Mtype)
					appSKey.UnmarshalText([]byte(activation.AppSKey))
					devAddr.UnmarshalText([]byte(payload.MacPayload.Fhdr.Devaddr))
					b, err := base64.StdEncoding.DecodeString(payload.MacPayload.FrmPayload[0].Bytes)
					if err != nil {
						log.Fatalf("could not base64 decode %v\n", err)
					}
					data, err := lorawan.EncryptFRMPayload(appSKey, isUplink(payload.Mhdr.Mtype), devAddr, payload.MacPayload.Fhdr.Fcnt, b)
					if err != nil {
						log.Fatalf("could not decrypt frame payload %v\n", err)
					}
					fmt.Printf("\tContent:\t%d %T %b 0x%X \"%s\"\n", len(data), data, data, data, string(data))
				}
			}
		}
	}
}
