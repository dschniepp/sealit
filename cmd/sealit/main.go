package main

import (
	"log"
	"os"

	"github.com/dschniepp/sealit/internal"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "sealit",
		Usage: "alternative cli for sealed secrets",
		Commands: []*cli.Command{
			{
				Name:    "init",
				Aliases: []string{"i"},
				Usage:   "create a config file in the current dir",
				Action: func(c *cli.Context) error {
					return internal.Init(c.String("config"), c.Bool("force"))
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Value: false,
						Usage: "overwrite existing config file",
					},
				},
			},
			{
				Name:    "seal",
				Aliases: []string{"s"},
				Usage:   "seal all secrets",
				Action: func(c *cli.Context) error {
					sealit := internal.New(c.String("config"), c.String("kubeconfig"))
					return sealit.Seal(c.Bool("force"))
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Value: false,
						Usage: "seal with old certificate",
					},
				},
			},
			{
				Name:    "verify",
				Aliases: []string{"v"},
				Usage:   "verify if all secrets are encrypted",
				Action: func(c *cli.Context) error {
					sealit := internal.New(c.String("config"), c.String("kubeconfig"))
					return sealit.Verify()
				},
			},
			{
				Name:    "template",
				Aliases: []string{"t"},
				Usage:   "create a sealed secrets template",
				Action: func(c *cli.Context) error {
					return internal.Template(c.String("file"))
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "file",
						Value: "",
						Usage: "file path for template",
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Value: ".sealit.yaml",
				Usage: "path to sealit config file",
			},
			&cli.StringFlag{
				Name:  "kubeconfig",
				Usage: "path to the kubeconfig file",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
