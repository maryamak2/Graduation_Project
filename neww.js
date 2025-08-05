async function submitPatient() {
    // Collect form data
    const formData = {
        User_ID: parseInt(document.getElementById('userID').value), // Convert to int
        Patient_ID_Clinical: parseInt(document.getElementById('patientClinicalID').value), // Convert to int
        Patient_ID_Billing: parseInt(document.getElementById('patientBillingID').value), // Convert to int
        Gender: document.getElementById('patientGender').value,
        Contact: document.getElementById('patientContact').value,
        Allergies: document.getElementById('allergies').value,
        Chronic_Conditions: document.getElementById('chronicConditions').value,
        Purpose_of_Visit: document.getElementById('purposeOfVisit').value,
        Prescribing_Doctor_ID: parseInt(document.getElementById('prescribingDoctorID').value), // Convert to int
    };

    // Send data to the backend
    try {
        const response = await fetch('http://localhost:8000/patients', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        });

        if (response.ok) {
            alert('Patient added successfully!');
            // Clear the form
            document.getElementById('patientForm').reset();
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.detail}`);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while submitting the form.');
    }
}