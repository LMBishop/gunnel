package store

import (
	"strings"
	"time"

	"github.com/LMBishop/gunnel/pkg/wireguard"
	"github.com/tjarratt/babble"
)

type ForwardingRule struct {
	Slug     string
	Peer     *wireguard.Peer
	Port     string
	LastUsed time.Time
}

type Service interface {
	GetRuleBySlug(slug string) *ForwardingRule
	NewForwardingRule(slug string, peer *wireguard.Peer, port string) *ForwardingRule
	RemoveForwardingRule(slug string)
	GetUnusedSlug() string
	GetUnusedRulesSince(since time.Time) []*ForwardingRule
}

type service struct {
	forwardingRules map[string]*ForwardingRule
}

func NewService() Service {
	return &service{
		forwardingRules: make(map[string]*ForwardingRule),
	}
}

func (s *service) GetRuleBySlug(slug string) *ForwardingRule {
	return s.forwardingRules[slug]
}

func (s *service) NewForwardingRule(slug string, peer *wireguard.Peer, port string) *ForwardingRule {
	if s.forwardingRules[slug] != nil {
		return nil
	}

	rule := &ForwardingRule{
		Slug: slug,
		Peer: peer,
		Port: port,
	}
	s.forwardingRules[slug] = rule
	return rule
}

func (s *service) GetUnusedSlug() string {
	b := babble.NewBabbler()
	b.Count = 3
	b.Separator = "-"

	for i := 0; i < 10; i++ {
		slug := strings.Replace(strings.ToLower(b.Babble()), "'", "", -1)
		if s.forwardingRules[slug] == nil {
			return slug
		}
	}

	return ""
}

func (s *service) GetUnusedRulesSince(since time.Time) []*ForwardingRule {
	var rules []*ForwardingRule
	for _, rule := range s.forwardingRules {
		if rule.LastUsed.Before(since) {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (s *service) RemoveForwardingRule(slug string) {
	delete(s.forwardingRules, slug)
}
