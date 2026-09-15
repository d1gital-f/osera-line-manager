// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package board reads the organisation's project board, the one place every CVE
// issue is on whatever repository it moved to. One GraphQL query per pass, paged
// at a hundred cards, whatever the number of CVEs. The board says where an issue
// lives (a producer took it), whether it is open, and which labels it carries.
package board

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Client reads one organisation project.
type Client struct {
	// Owner is the organisation login.
	Owner string
	// Number is the project number, as in its URL.
	Number int
	// Tokens gives the token for every request, refreshed by the App when it is about to expire;
	// nil sends no token.
	Tokens TokenSource
	HTTP   *http.Client
	// URL is GitHub's GraphQL endpoint, a test server in tests.
	URL string
	// ProjectID, StatusFieldID and Lanes (Status option name to id) are learnt by Read,
	// what a lane change needs.
	ProjectID     string
	StatusFieldID string
	Lanes         map[string]string
}

// New returns a client with sane timeouts.
// TokenSource gives a token to call GitHub with; the App is one.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a TokenSource that always answers the same, for tests and tools.
type StaticToken string

// Token is the string itself.
func (t StaticToken) Token(context.Context) (string, error) {
	return string(t), nil
}

func New(owner string, number int, tokens TokenSource) *Client {
	return &Client{
		Owner:  owner,
		Number: number,
		Tokens: tokens,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		URL:    "https://api.github.com/graphql",
	}
}

// Card is one issue on the board, as the line manager reads it.
type Card struct {
	CVE        string   `json:"cve"`
	Number     int      `json:"number"`
	Title      string   `json:"title"`
	State      string   `json:"state"`
	Repository string   `json:"repository"`
	URL        string   `json:"url"`
	Labels     []string `json:"labels"`
	// ItemID is the card's own id on the board, what a lane change is addressed to.
	ItemID string `json:"item_id,omitempty"`
	// Lane is the card's Status on the board as named there, empty when unset.
	Lane string `json:"lane,omitempty"`
}

// NotRemediableLabel is the label a producer puts on an issue to say the CVE
// cannot be fixed on the line. The reason is in their comment.
const NotRemediableLabel = "not remediable"

var cveInTitle = regexp.MustCompile(`(CVE-[0-9]{4}-[0-9]+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})`)

const query = `query($owner: String!, $number: Int!, $after: String) {
  organization(login: $owner) {
    projectV2(number: $number) {
      id
      field(name: "Status") {
        ... on ProjectV2SingleSelectField { id options { id name } }
      }
      items(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          fieldValueByName(name: "Status") {
            ... on ProjectV2ItemFieldSingleSelectValue { name }
          }
          content {
            __typename
            ... on Issue {
              number
              title
              state
              url
              repository { name }
              labels(first: 20) { nodes { name } }
            }
          }
        }
      }
    }
  }
}`

// page is the shape of one GraphQL answer.
type page struct {
	Data struct {
		Organization struct {
			ProjectV2 struct {
				ID    string `json:"id"`
				Field struct {
					ID      string `json:"id"`
					Options []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"options"`
				} `json:"field"`
				Items struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						ID               string `json:"id"`
						FieldValueByName struct {
							Name string `json:"name"`
						} `json:"fieldValueByName"`
						Content struct {
							TypeName   string `json:"__typename"`
							Number     int    `json:"number"`
							Title      string `json:"title"`
							State      string `json:"state"`
							URL        string `json:"url"`
							Repository struct {
								Name string `json:"name"`
							} `json:"repository"`
							Labels struct {
								Nodes []struct {
									Name string `json:"name"`
								} `json:"nodes"`
							} `json:"labels"`
						} `json:"content"`
					} `json:"nodes"`
				} `json:"items"`
			} `json:"projectV2"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Read returns every card of the board whose content is an issue with a CVE in
// the title. Anything else on the board is skipped.
func (c *Client) Read(ctx context.Context) ([]Card, error) {
	var cards []Card
	after := ""
	for {
		// 1. one page of a hundred items
		p, err := c.page(ctx, after)
		if err != nil {
			return nil, err
		}
		if after == "" {
			c.ProjectID = p.Data.Organization.ProjectV2.ID
			c.StatusFieldID = p.Data.Organization.ProjectV2.Field.ID
			c.Lanes = map[string]string{}
			for _, o := range p.Data.Organization.ProjectV2.Field.Options {
				c.Lanes[o.Name] = o.ID
			}
		}

		// 2. one card per issue with a CVE in the title
		for _, n := range p.Data.Organization.ProjectV2.Items.Nodes {
			if n.Content.TypeName != "Issue" {
				continue
			}
			cve := cveInTitle.FindString(n.Content.Title)
			if cve == "" {
				continue
			}
			card := Card{
				CVE:        cve,
				Number:     n.Content.Number,
				Title:      n.Content.Title,
				State:      n.Content.State,
				Repository: n.Content.Repository.Name,
				URL:        n.Content.URL,
				Labels:     []string{},
				ItemID:     n.ID,
				Lane:       n.FieldValueByName.Name,
			}
			for _, l := range n.Content.Labels.Nodes {
				card.Labels = append(card.Labels, l.Name)
			}
			cards = append(cards, card)
		}

		// 3. the next page, or done
		if !p.Data.Organization.ProjectV2.Items.PageInfo.HasNextPage {
			return cards, nil
		}
		after = p.Data.Organization.ProjectV2.Items.PageInfo.EndCursor
	}
}

// page runs the query once, from the cursor given.
func (c *Client) page(ctx context.Context, after string) (*page, error) {
	// 1. the request
	variables := map[string]any{"owner": c.Owner, "number": c.Number}
	if after != "" {
		variables["after"] = after
	}
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Tokens != nil {
		token, err := c.Tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("the board's token: %w", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	// 2. the answer
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading the board: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading the board: HTTP %d", resp.StatusCode)
	}
	var p page
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("reading the board: %w", err)
	}

	// 3. GraphQL reports errors in the body with a 200
	if len(p.Errors) > 0 {
		return nil, fmt.Errorf("reading the board: %s", p.Errors[0].Message)
	}
	return &p, nil
}

// Issues turns the cards into what the status computation reads: one Issue per
// CVE. When a CVE has more than one card the one outside the backlog repository
// wins, it is the one a producer took.
func Issues(cards []Card, backlogRepository string) []status.Issue {
	// 1. one issue per CVE, the patch repository wins over the backlog
	found := map[string]status.Issue{}
	order := []string{}
	for _, card := range cards {
		is := status.Issue{
			CVE:           card.CVE,
			Repository:    card.Repository,
			Number:        card.Number,
			State:         card.State,
			NotRemediable: hasLabel(card.Labels, NotRemediableLabel),
			ItemID:        card.ItemID,
			Lane:          card.Lane,
		}
		prev, seen := found[card.CVE]
		if !seen {
			found[card.CVE] = is
			order = append(order, card.CVE)
			continue
		}
		if prev.Repository == backlogRepository && card.Repository != backlogRepository {
			found[card.CVE] = is
		}
	}

	// 2. as a list, in the order the board gave them
	out := make([]status.Issue, 0, len(found))
	for _, cve := range order {
		out = append(out, found[cve])
	}
	return out
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// LaneOption is the id of the Status option whose name matches, letter case aside;
// empty when the board has no such lane. Read must have run.
func (c *Client) LaneOption(name string) string {
	for n, id := range c.Lanes {
		if strings.EqualFold(n, name) {
			return id
		}
	}
	return ""
}

const setLaneMutation = `mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field, value: {singleSelectOptionId: $option}}) {
    projectV2Item { id }
  }
}`

// SetLane puts a card in the lane given by its Status option id. One mutation per card.
func (c *Client) SetLane(ctx context.Context, itemID, optionID string) error {
	body, err := json.Marshal(map[string]any{"query": setLaneMutation, "variables": map[string]any{
		"project": c.ProjectID, "item": itemID, "field": c.StatusFieldID, "option": optionID}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Tokens != nil {
		token, err := c.Tokens.Token(ctx)
		if err != nil {
			return fmt.Errorf("the board's token: %w", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("moving the card: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("moving the card: HTTP %d", resp.StatusCode)
	}
	var answer struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return fmt.Errorf("moving the card: %w", err)
	}
	if len(answer.Errors) > 0 {
		return fmt.Errorf("moving the card: %s", answer.Errors[0].Message)
	}
	return nil
}
