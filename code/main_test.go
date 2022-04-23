package main

import (
	"testing"
	"time"
)

func TestStamperTrue(t *testing.T) {

	fifty := time.Now().Add((-50) * time.Second)
	thirty := time.Now().Add((-30) * time.Second)
	fiftynine := time.Now().Add((-59) * time.Second)

	timestamps := []time.Time{fiftynine, thirty, fifty}

	for _, d := range timestamps {
		timestamps := []time.Time{d}
		if !stamper("100.64.0.1", timestamps) {
			t.Errorf("Expected true, got false")
		}
	}

}

func TestStamperFalse(t *testing.T) {
	fifteen := time.Now().Add((-15) * time.Minute)
	ten := time.Now().Add((-10) * time.Minute)
	nintey := time.Now().Add((-90) * time.Second)

	timestamps := []time.Time{fifteen, ten, nintey}

	for _, d := range timestamps {
		timestamps := []time.Time{d}
		if stamper("100.64.0.1", timestamps) {
			t.Errorf("Expected false, got true")
		}
	}
}

// TODO write tests for portCompare
