package main

import (
	"log"
	"os"
	"time"

	"github.com/dschniepp/sealit/internal"

	"github.com/hashicorp/logutils"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:     "sealit",
		Version:  "v0.4.0",
		Compiled: time.Now(),
		Usage:    "alternative cli for sealed secrets",
		Commands: []*cli.Command{
			{
				Name:    "init",
				Aliases: []string{"i"},
				Usage:   "create a config file in the current dir",
				Action: func(c *cli.Context) (err error) {
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
				Action: func(c *cli.Context) (err error) {
					sealit, err := internal.New(c.String("config"), c.String("kubeconfig"), c.Bool("fetch-cert"))
					if err != nil {
						return err
					}

					return sealit.Seal(c.Bool("force"))
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Value: false,
						Usage: "seal with old certificate",
					},
					&cli.BoolFlag{
						Name:  "fetch-cert",
						Value: false,
						Usage: "fetch latest cert from source",
					},
				},
			},
			{
				Name:    "reseal",
				Aliases: []string{"r"},
				Usage:   "reseal all secrets with the newest public cert",
				Action: func(c *cli.Context) (err error) {
					sealit, err := internal.New(c.String("config"), c.String("kubeconfig"), true)
					if err != nil {
						return err
					}

					return sealit.Reseal()
				},
			},
			{
				Name:    "verify",
				Aliases: []string{"v"},
				Usage:   "verify if all secrets are encrypted",
				Action: func(c *cli.Context) (err error) {
					sealit, err := internal.New(c.String("config"), c.String("kubeconfig"), c.Bool("fetch-cert"))
					if err != nil {
						return err
					}
					return sealit.Verify()
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "fetch-cert",
						Value: false,
						Usage: "fetch latest cert from source",
					},
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
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
				Usage: "enable verbose output",
			},
		},
		Before: func(c *cli.Context) (err error) {
			filter := &logutils.LevelFilter{
				Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
				MinLevel: logutils.LogLevel("WARN"),
				Writer:   os.Stderr,
			}

			if c.Bool("debug") {
				filter.MinLevel = "DEBUG"
			}

			log.SetOutput(filter)

			return err
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
