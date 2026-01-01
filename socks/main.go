package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	// "net/netip"
	"os"
	"slices"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/samber/lo"
	"github.com/things-go/go-socks5"
	"github.com/urfave/cli/v2"
	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/proxy"
)

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

func init() {
	initGlog()
}

func initGlog() {
	// flag.Set("logtostderr", "true")
	flag.Set("alsologtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Set("v", "0")
	// flag.Set("v", "2") // verbose
	// unlike unix, the android/ios standard is for diagnostics to go to stdout
	os.Stderr = os.Stdout
}

func main() {
	cfg := struct {
		addr        string
		apiURL      string
		platformURL string
		userAuth    string
		password    string
		authJwt     string
		providerID  string
		city        string
		country     string
		region      string
	}{}
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "addr",
				Usage:       "Socks5 server address",
				EnvVars:     []string{"ADDR"},
				Destination: &cfg.addr,
				Value:       ":9999",
			},
			&cli.StringFlag{
				Name:        "api-url",
				Usage:       "API URL",
				EnvVars:     []string{"API_URL"},
				Destination: &cfg.apiURL,
				Value:       "https://api.bringyour.com",
			},
			&cli.StringFlag{
				Name:        "platform-url",
				Usage:       "Platform URL",
				EnvVars:     []string{"PLATFORM_URL"},
				Destination: &cfg.platformURL,
				Value:       "wss://connect.bringyour.com",
			},
			&cli.StringFlag{
				Name:        "user-auth",
				Usage:       "User auth",
				EnvVars:     []string{"USER_AUTH"},
				Destination: &cfg.userAuth,
			},
			&cli.StringFlag{
				Name:        "password",
				Usage:       "Password",
				EnvVars:     []string{"PASSWORD"},
				Destination: &cfg.password,
			},
			&cli.StringFlag{
				Name:        "authjwt",
				Usage:       "AuthJWT",
				EnvVars:     []string{"AUTHJWT"},
				Destination: &cfg.authJwt,
			},
			&cli.StringFlag{
				Name:        "provider-id",
				Usage:       "Provider ID",
				EnvVars:     []string{"PROVIDER_ID"},
				Destination: &cfg.providerID,
			},
			&cli.StringFlag{
				Name:        "city",
				Usage:       "City",
				EnvVars:     []string{"CITY"},
				Destination: &cfg.city,
			},
			&cli.StringFlag{
				Name:        "country",
				Usage:       "Country",
				EnvVars:     []string{"COUNTRY"},
				Destination: &cfg.country,
			},
			&cli.StringFlag{
				Name:        "region",
				Usage:       "Region",
				EnvVars:     []string{"REGION"},
				Destination: &cfg.region,
			},
		},
		Name: "socksproxy",
		Action: func(c *cli.Context) error {
			ctx := c.Context
			var jwt string
			var err error
			if cfg.authJwt != "" {
				jwt = cfg.authJwt
			} else if cfg.password != "" && cfg.userAuth != "" {
				jwt, err = login(ctx, cfg.apiURL, cfg.userAuth, cfg.password)
				if err != nil {
					return fmt.Errorf("login failed: %w", err)
				}
			} else {
				return fmt.Errorf("Either use AuthJWT or use user auth + password\n")
			}

			// [TODO] regularly check balance?
			res, err := subscriptionBalance(ctx, cfg.apiURL, jwt)
			if err != nil {
				return fmt.Errorf("Get subscription balance failed %w", err)
			} else {
				fmt.Printf("Subscription: %+v\n", res)
				fmt.Printf("Available: %d MB\nUsed: %d MB\nPending: %d MB \nTotal: %d MB\n",
					res.BalanceByteCount/1024.0/1024.0,
					(res.StartBalanceByteCount-res.BalanceByteCount-res.OpenTransferByteCount)/1024.0/1024.0,
					res.OpenTransferByteCount/1024.0/1024.0,
					res.StartBalanceByteCount/1024.0/1024.0,
				)

			}

			locations, err := getProviderLocations(
				ctx,
				cfg.apiURL,
				jwt,
			)
			if err != nil {
				return fmt.Errorf("get locations failed: %w", err)
			}

			providersSpec, err := getProviderSpec(
				locations,
				cfg.city,
				cfg.country,
				cfg.region,
				cfg.providerID,
			)
			if err != nil {
				return fmt.Errorf("get provider spec failed: %w", err)
			}

			// if jwt already is client jwt (contains clientid), we don't need to fetch new one.
			// TODO and we shoud refresh it
			// So in connectl , we should generate jwt and also client jwt
			var clientJWT string
			if _, err := parseByJwtClientId(jwt); err == nil {
				fmt.Println("JWT from arguments already is clientJWT")
				clientJWT = jwt
			} else {
				clientJWT, err = authNetworkClient(
					ctx,
					cfg.apiURL,
					jwt,
					&connect.AuthNetworkClientArgs{
						Description: "my device",
						DeviceSpec:  "socks5",
					},
				)
				if err != nil {
					return fmt.Errorf("auth network client failed: %w", err)
				}
			}

			clientID, err := parseByJwtClientId(clientJWT)
			if err != nil {
				return fmt.Errorf("parse byJwt client id failed: %w", err)
			}

			fmt.Println("my clientID:", clientID)
			fmt.Println("my clientjwt:", clientJWT)

			// refresh client jwt???

			// refreshjwt, err := refreshJwt(ctx, cfg.apiURL, clientJWT)
			// if err != nil {
			// 	return fmt.Errorf("Refresh JWT failed %w", err)
			// } else {
			// 	if refreshjwt.Error != nil {
			// 		fmt.Printf("New jwt %s\n", refreshjwt.Error.Message)
			// 	} else {
			// 		fmt.Printf("New jwt %s\n", refreshjwt.ByJwt)
			// 	}
			// }

			generator := connect.NewApiMultiClientGenerator(
				ctx,
				providersSpec,
				connect.NewClientStrategyWithDefaults(ctx),
				// exclude self
				[]connect.Id{
					clientID,
				},
				cfg.apiURL,
				clientJWT,
				cfg.platformURL,
				"my device",
				"socks5",
				"0.0.0",
				&clientID,
				// connect.DefaultClientSettingsNoNetworkEvents,
				connect.DefaultClientSettings,
				connect.DefaultApiMultiClientGeneratorSettings(),
			)

			dev, err := proxy.CreateTunWithDefaults(ctx)
			if err != nil {
				return fmt.Errorf("create net tun failed: %w", err)
			}

			mc := connect.NewRemoteUserNatMultiClientWithDefaults(
				ctx,
				generator,
				func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
					_, err := dev.Write(packet)
					if err != nil {
						fmt.Println("packet write error:", err)
					}
				},
				protocol.ProvideMode_Network,
			)

			source := connect.SourceId(clientID)

			go func() {
				for {
					packet, err := dev.Read()
					if err == nil {
						mc.SendPacket(
							source,
							protocol.ProvideMode_Network,
							packet,
							time.Second*15,
						)
					}
					if err != nil {
						fmt.Println("read error:", err)
						return
					}
				}
			}()

			server := socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {

					fmt.Println("Dialing", network, addr, request.RawDestAddr.FQDN)

					// ap, err := netip.ParseAddrPort(addr)
					// if err != nil {
					// 	return nil, err
					// }

					return dev.DialContext(ctx, "tcp", addr)
				}),
			)

			go server.ListenAndServe("tcp", cfg.addr)

			fmt.Printf("socks5 server is listening on %s\n", cfg.addr)

			<-ctx.Done()

			return nil

		},
	}
	app.RunAndExitOnError()

}

func getProviderSpec(
	locations *FindLocationsResult,
	city string,
	country string,
	region string,
	providerID string,
) ([]*connect.ProviderSpec, error) {

	if providerID != "" {
		cid, err := connect.ParseId(providerID)
		if err != nil {
			return nil, fmt.Errorf("parse provider id failed: %w", err)
		}

		fmt.Println("provider match", cid)

		return []*connect.ProviderSpec{
			{
				ClientId: &cid,
			},
		}, nil
	}

	if city != "" {
		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "city":
				if strings.ToLower(v.Name) == strings.ToLower(city) {
					fmt.Printf("city matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	if country != "" {

		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "country":
				if strings.ToLower(v.Name) == strings.ToLower(country) {
					fmt.Printf("country matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	if region != "" {

		for _, v := range locations.Locations.Values() {

			switch v.LocationType {
			case "region":
				if strings.ToLower(v.Name) == strings.ToLower(region) {
					fmt.Printf("region matched %q, provider count %d\n", v.Name, v.ProviderCount)
					return []*connect.ProviderSpec{
						{
							LocationId: v.LocationId,
						},
					}, nil
				}
			}

		}
	}

	regions := lo.Filter(locations.Locations.Values(), func(v *LocationResult, _ int) bool {
		return v.LocationType == "region"
	})

	cities := lo.Filter(locations.Locations.Values(), func(v *LocationResult, _ int) bool {
		return v.LocationType == "city"
	})

	countries := lo.Filter(locations.Locations.Values(), func(v *LocationResult, _ int) bool {
		return v.LocationType == "country"
	})

	uniqNames := func(locations []*LocationResult) []string {
		names := lo.Map(locations, func(v *LocationResult, _ int) string {
			return v.Name
		})
		slices.Sort(names)
		return lo.Uniq(names)
	}

	prefixEach := func(prefix string, names []string) []string {
		return lo.Map(names, func(v string, _ int) string {
			return prefix + v
		})
	}

	return nil, fmt.Errorf(
		`please specify a location: city, country, region or provider id from this list:
 countries:
%s
 regions:
%s
 cities:
%s`,
		strings.Join(prefixEach("  ", uniqNames(countries)), "\n"),
		strings.Join(prefixEach("  ", uniqNames(regions)), "\n"),
		strings.Join(prefixEach("  ", uniqNames(cities)), "\n"),
	)

}

func login(ctx context.Context, apiURL, userAuth, password string) (string, error) {
	api := connect.NewBringYourApi(
		ctx,
		connect.NewClientStrategyWithDefaults(ctx),
		apiURL,
	)

	// api.AuthNetworkClient()
	type loginResult struct {
		res *connect.AuthLoginWithPasswordResult
		err error
	}

	resChan := make(chan loginResult)

	api.AuthLoginWithPassword(
		&connect.AuthLoginWithPasswordArgs{
			UserAuth: userAuth,
			Password: password,
		},
		connect.NewApiCallback(
			func(res *connect.AuthLoginWithPasswordResult, err error) {
				resChan <- loginResult{res, err}
			},
		),
	)

	res := <-resChan
	if res.res.Error != nil {
		return "", errors.New(res.res.Error.Message)
	}

	if res.res.VerificationRequired != nil {
		return "", errors.New("verification required")
	}

	return res.res.Network.ByJwt, nil

}

// Copied from sdk/api.go
type ByteCount = int64
type NanoCents = int64
type Subscription struct {
	SubscriptionId string `json:"subscription_id"`
	Store          string `json:"store"`
	Plan           string `json:"plan"`
}
type TransferBalance struct {
	BalanceId             string    `json:"balance_id"`
	NetworkId             string    `json:"network_id"`
	StartTime             string    `json:"start_time"`
	EndTime               string    `json:"end_time"`
	StartBalanceByteCount ByteCount `json:"start_balance_byte_count"`
	// how much money the platform made after subtracting fees
	NetRevenue       NanoCents `json:"net_revenue"`
	BalanceByteCount ByteCount `json:"balance_byte_count"`
}

type SubscriptionBalanceResult struct {
	/*
	 * StartBalanceByteCount - The available balance the user starts the day with
	 */
	StartBalanceByteCount ByteCount `json:"start_balance_byte_count"`
	/**
	 * BalanceByteCount - The remaining balance the user has available
	 */
	BalanceByteCount ByteCount `json:"balance_byte_count"`
	/**
	 * OpenTransferByteCount - The total number of bytes tied up in open transfers
	 */
	OpenTransferByteCount     ByteCount          `json:"open_transfer_byte_count"`
	CurrentSubscription       *Subscription      `json:"current_subscription,omitempty"`
	ActiveTransferBalances    *[]TransferBalance `json:"active_transfer_balances,omitempty"`
	PendingPayoutUsdNanoCents NanoCents          `json:"pending_payout_usd_nano_cents"`
	UpdateTime                string             `json:"update_time"`
}

func subscriptionBalance(ctx context.Context, apiURL string, jwt string) (*SubscriptionBalanceResult, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpGetWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/subscription/balance", apiURL),
		jwt,
		&SubscriptionBalanceResult{},
		connect.NewNoopApiCallback[*SubscriptionBalanceResult](),
	)
}

type RefreshJwtResultError struct {
	Message string `json:"message"`
}

type RefreshJwtResult struct {
	ByJwt string                 `json:"by_jwt,omitempty"`
	Error *RefreshJwtResultError `json:"error,omitempty"`
}

func refreshJwt(ctx context.Context, apiURL string, jwt string) (*RefreshJwtResult, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpGetWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/auth/refresh", apiURL),
		jwt,
		&RefreshJwtResult{},
		connect.NewNoopApiCallback[*RefreshJwtResult](),
	)

}

func getProviderLocations(ctx context.Context, apiURL string, jwt string) (*FindLocationsResult, error) {

	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpGetWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/provider-locations", apiURL),
		jwt,
		&FindLocationsResult{},
		connect.NewNoopApiCallback[*FindLocationsResult](),
	)

}

// func (self *BringYourApi) FindProviders(findProviders *FindProvidersArgs, callback FindProvidersCallback) {
// 	go connect.HandleError(func() {
// 		connect.HttpPostWithStrategy(
// 			self.ctx,
// 			self.clientStrategy,
// 			fmt.Sprintf("%s/network/find-providers", self.apiUrl),
// 			findProviders,
// 			self.GetByJwt(),
// 			&FindProvidersResult{},
// 			callback,
// 		)
// 	})
// }

func findProviders(ctx context.Context, apiURL string, jwt string, args *FindProvidersArgs) (*FindProvidersResult, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	return connect.HttpPostWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/find-providers", apiURL),
		args,
		jwt,
		&FindProvidersResult{},
		connect.NewNoopApiCallback[*FindProvidersResult](),
	)
}

func authNetworkClient(ctx context.Context, apiURL, jwt string, req *connect.AuthNetworkClientArgs) (string, error) {
	strategy := connect.NewClientStrategyWithDefaults(ctx)

	res, err := connect.HttpPostWithStrategy(
		ctx,
		strategy,
		fmt.Sprintf("%s/network/auth-client", apiURL),
		req,
		jwt,
		&connect.AuthNetworkClientResult{},
		connect.NewNoopApiCallback[*connect.AuthNetworkClientResult](),
	)

	if err != nil {
		return "", err
	}

	if res.Error != nil {
		return "", errors.New(res.Error.Message)
	}

	return res.ByClientJwt, nil
}

func parseByJwtClientId(byJwt string) (connect.Id, error) {
	claims := gojwt.MapClaims{}
	gojwt.NewParser().ParseUnverified(byJwt, claims)

	jwtClientId, ok := claims["client_id"]
	if !ok {
		return connect.Id{}, fmt.Errorf("byJwt does not contain claim client_id")
	}
	switch v := jwtClientId.(type) {
	case string:
		return connect.ParseId(v)
	default:
		return connect.Id{}, fmt.Errorf("byJwt hav invalid type for client_id: %T", v)
	}
}
